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
