<?php
/**
 * Minimal "default install" style PHP app for the phpAfterShell lab.
 *
 * - Uses PHP's default file-based sessions (session.save_handler = files).
 * - Stores a user-supplied string in $_SESSION (typical app behaviour:
 *   profile/bio/cart data). This is the "carrier" record used by the POC.
 * - GET acts as the consumer/oracle: it reports exactly what the session
 *   decoder produced after session_start(), which is what an attacker
 *   would inherit on any later request.
 */
require_once __DIR__ . '/gadget.php';   // autoload-style: class must exist
                                       // before the session decoder runs

// Lab helper for the exploit's controller: clear stored session files so
// the target's page-cache pool stays deterministic between attempts.
// (Diagnostic endpoint of the bundled demo app; real targets don't have it
// - the exploit treats a missing gc endpoint as a no-op.)
if (isset($_GET['gc'])) {
    $dir = session_save_path() ?: sys_get_temp_dir();
    $n = 0;
    foreach ((glob($dir . '/sess_*') ?: []) as $f) {
        if (@unlink($f)) { $n++; }
    }
    header('Content-Type: application/json');
    echo json_encode(['gc' => $n]);
    exit;
}

// Eviction helper for the exploit's controller (phase-1 lab endpoint,
// like gc: real targets do not have it and the exploit treats its absence
// as a no-op). Runs sessdrop(1) - which evicts the record's clean page
// cache in a loop - while the victim request rewrites it, so the pwrite
// re-creates - re-charges - those pages and the cgroup crosses its limit
// *inside* the splice window. Same eviction the local stage-2 controller
// performs with fadvise(2), reached over HTTP.
// Baseline probe for the exploit's controller (phase-1 lab endpoint,
// like gc/drop: real targets do not have it and the exploit treats its
// absence as a no-op). Reports the live cgroup charge while THIS request
// runs - i.e. after the fillers are loaded and before the victim starts,
// the only moment the pressure-relevant baseline can be read. The reply
// includes the request's own RSS so the caller can subtract costs that
// are not part of the baseline.
if (isset($_GET['probe'])) {
    header('Content-Type: application/json');
    $self = 0;
    $st = @file_get_contents('/proc/self/statm');
    if ($st !== false) {
        $parts = preg_split('/\s+/', trim($st));
        if (count($parts) >= 2) {
            $self = (int) $parts[1] * 4096;   // resident pages
        }
    }
    echo json_encode([
        'mem'  => (int) @file_get_contents('/sys/fs/cgroup/memory.current'),
        'self' => $self,
    ]);
    exit;
}

if (isset($_GET['drop'])) {
    header('Content-Type: application/json');
    // Measure the cgroup here, with this process already live: this is
    // the state the victim request is about to enter, drop worker
    // included. The exploit anchors its pressure correction on this.
    $mem = (int) @file_get_contents('/sys/fs/cgroup/memory.current');
    $sid = preg_replace('/[^a-f0-9]/', '', (string) $_GET['drop']);
    $ms  = min(8000, max(100, (int) ($_GET['ms'] ?? 4000)));
    $path = (session_save_path() ?: sys_get_temp_dir()) . '/sess_' . $sid;
    $ok = false;
    if ($sid !== '' && is_executable('/usr/local/bin/sessdrop')) {
        // blocks for $ms while the helper evicts in a loop
        @shell_exec('/usr/local/bin/sessdrop ' . escapeshellarg($path)
                    . ' ' . $ms);
        $ok = true;
    }
    echo json_encode(['drop' => $ok ? 1 : 0, 'ok' => $ok, 'mem' => $mem]);
    exit;
}

session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && array_key_exists('bio', $_POST)) {
    $_SESSION['bio'] = (string) $_POST['bio'];
    header('Content-Type: text/plain');
    echo 'stored:' . strlen($_SESSION['bio']);
    exit;
}

header('Content-Type: application/json');
$report = [
    'php'   => PHP_VERSION,
    // Live cgroup baseline (phase-1 diagnostic): the exploit corrects its
    // pressure by this every attempt, so the OOM lands in the same place
    // regardless of the host's baseline drift (worker arena recycling
    // moves it ~1-2MiB between attempts). Read before the session file
    // below so it reflects the baseline, not the file cache.
    'mem'   => (int) @file_get_contents('/sys/fs/cgroup/memory.current'),
    'keys'  => [],
    'types' => [],
    'objects' => [],
];
foreach ($_SESSION as $k => $v) {
    $report['keys'][] = $k;
    $report['types'][$k] = get_debug_type($v);
    if (is_object($v)) {
        $report['objects'][$k] = [
            'class' => get_class($v),
            'props' => (array) $v,
        ];
    }
    if (is_array($v) && strpos($k, 'upload_progress_') === 0) {
        $fn = $v['files'][0]['field_name'] ?? '';
        $nm = $v['files'][0]['name'] ?? '';
        $report['flen'] = strlen($fn);
        $report['nlen'] = strlen($nm);
    }
}

// Raw-state diagnostics for the PoC controller: size of the session file and
// the length of the trailing run of 'G' bytes that R's filename consists of.
// A truncated run marks the exact splice offset k = gstart + glen.
$sessDir = session_save_path();
if ($sessDir === '' || $sessDir === '0') {
    $sessDir = sys_get_temp_dir();
}
$raw = @file_get_contents($sessDir . '/sess_' . session_id());
$report['size'] = ($raw === false) ? -1 : strlen($raw);
$report['gstart'] = null;
$report['glen'] = null;
if ($raw !== false && preg_match('/G{64,}/', $raw, $m, PREG_OFFSET_CAPTURE)) {
    $report['gstart'] = $m[0][1];
    $report['glen']   = strlen($m[0][0]);
}
echo json_encode($report, JSON_PRETTY_PRINT);
