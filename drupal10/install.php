<?php
/**
 * First-boot installer for the Drupal 10 lab target.
 *
 * Drives Drupal's own web installer over HTTP from inside the
 * container - exactly the requests a browser would send: the language,
 * profile and database forms (SQLite), the profile-modules batch
 * through its own JS protocol (op=do polls + op=finished), and the
 * site configuration form. One process = one cookie session, which
 * the batch is bound to (measured: a second process gets "No batch
 * with ID 1 exists"). No CLI bootstrap, no direct database writes,
 * no helper endpoints: the site is installed the stock way.
 *
 * Idempotent: exits 0 when the site already answers with its name.
 * Any failure prints the page title and exits non-zero so the
 * image build / healthcheck stays red.
 */

$BASE = 'http://127.0.0.1';
$trace = array();   // redirect chain of the last fetch (for failures)
$SITE_NAME = 'phpAfterShell lab';
$SQLITE = '/opt/drupal/web/sites/default/files/.ht.sqlite';
$SQLITE_DRIVER = 'Drupal\\sqlite\\Driver\\Database\\sqlite';
$jar = array();

function fetch($url, $data = null, $timeout = 300)
{
    global $jar, $BASE;
    if (strpos($url, 'http') !== 0) {
        $url = $BASE . ($url[0] === '/' ? '' : '/') . $url;
    }
    $GLOBALS['trace'] = array();
    $content = ($data === null) ? null : http_build_query($data);
    $GLOBALS['last_content'] = (string) $content;
    $GLOBALS['last_url'] = $url;
    // A User-Agent, like any real client sends: without one D10's
    // install_begin_request hits str_contains(null) and the
    // deprecation text is printed IN FRONT of the batch's JSON
    // response (measured: json_decode fails on the prefix).
    $headers = "Accept: */*\r\n"
             . "User-Agent: Mozilla/5.0 (X11; Linux x86_64) install-check\r\n";
    if ($jar) {
        $pairs = array();
        foreach ($jar as $k => $v) {
            $pairs[] = $k . '=' . $v;
        }
        $headers .= 'Cookie: ' . implode('; ', $pairs) . "\r\n";
    }
    if ($content !== null) {
        $headers .= "Content-Type: application/x-www-form-urlencoded\r\n";
    }
    // Redirects are followed MANUALLY: PHP's wrapper only exposes the
    // headers of the FINAL response, so a Set-Cookie on an
    // intermediate 302 would be lost - and the install batch (like
    // Drupal's form rebuilds) is bound to the session, so one lost
    // cookie means "No batch with ID 1 exists" (measured - the same
    // root cause as the Drupal 7 driver).
    $body = '';
    for ($hop = 0; $hop < 8; $hop++) {
        $ctx = stream_context_create(array('http' => array(
            'method' => ($content === null) ? 'GET' : 'POST',
            'header' => $headers,
            'content' => ($content === null) ? '' : $content,
            'timeout' => $timeout,
            'follow_location' => 0,
            'ignore_errors' => true,
        )));
        $body = @file_get_contents($url, false, $ctx);
        $status = 0;
        $location = null;
        foreach ($http_response_header as $h) {
            if (preg_match('#HTTP/\S+ (\d+)#', $h, $m)) {
                $status = (int) $m[1];
                $GLOBALS['trace'][] = trim($h);
            } elseif (stripos($h, 'location:') === 0) {
                $location = trim(substr($h, 9));
                $GLOBALS['trace'][] = '-> ' . $location;
            } elseif (stripos($h, 'set-cookie:') === 0) {
                $kv = explode(';', substr($h, 11));
                $pair = explode('=', $kv[0], 2);
                if (count($pair) === 2) {
                    $jar[trim($pair[0])] = trim($pair[1]);
                }
            }
        }
        if ($jar) {
            $pairs = array();
            foreach ($jar as $k => $v) {
                $pairs[] = $k . '=' . $v;
            }
            $headers = preg_replace('/Cookie: [^\r\n]*\r\n?/', '', $headers);
            $headers .= 'Cookie: ' . implode('; ', $pairs) . "\r\n";
        }
        if ($status >= 300 && $status < 400 && $location !== null) {
            $url = $location;
            $content = null;   // browsers turn the POST into a GET
            $headers = preg_replace('/Content-Type: [^\r\n]*\r\n?/', '', $headers);
            $headers = preg_replace('/Content-Length: [^\r\n]*\r\n?/', '', $headers);
            continue;
        }
        $GLOBALS['last_html'] = ($body === false) ? '' : $body;
        return array($body === false ? '' : $body, $url);
    }
    $GLOBALS['last_html'] = ($body === false) ? '' : $body;
    return array($body === false ? '' : $body, $url);
}

function page_title($html)
{
    return preg_match('/<title>([^<]*)<\/title>/', $html, $m) ? $m[1] : '?';
}

/** Every form control: hidden + checked radios/checkboxes + text-ish
 *  inputs with a value + selects, then the caller's overrides. Drupal
 *  10 puts data-* attributes before type, so match by search. */
function fill($html, $overrides = array())
{
    $d = array();
    if (preg_match_all('/<(?:input|select)[^>]*>/', $html, $tags)) {
        foreach ($tags[0] as $tag) {
            if (!preg_match('/name="([^"]+)"/', $tag, $n)) {
                continue;
            }
            $type = preg_match('/type="([^"]+)"/', $tag, $t) ? $t[1] : 'text';
            $has_value = preg_match('/value="([^"]*)"/', $tag, $v);
            if ($type === 'hidden') {
                $d[$n[1]] = $has_value ? $v[1] : '';
            } elseif (($type === 'radio' || $type === 'checkbox') && strpos($tag, 'checked') !== false) {
                if (!isset($d[$n[1]])) {
                    $d[$n[1]] = $has_value ? $v[1] : '1';
                }
            } elseif (in_array($type, array('text', 'password', 'number', 'email')) && $has_value) {
                if (!isset($d[$n[1]])) {
                    $d[$n[1]] = $v[1];
                }
            }
        }
    }
    if (preg_match_all('/<select[^>]*name="([^"]+)"[^>]*>(.*?)<\/select>/s', $html, $sels, PREG_SET_ORDER)) {
        foreach ($sels as $sel) {
            if (preg_match('/<option[^>]*selected[^>]*value="([^"]*)"/', $sel[2], $o) ||
                preg_match('/<option[^>]*value="([^"]*)"/', $sel[2], $o)) {
                if (!isset($d[$sel[1]])) {
                    $d[$sel[1]] = $o[1];
                }
            }
        }
    }
    return array_merge($d, $overrides);
}

function step($label, $ok, $detail = '')
{
    echo "[install] $label" . ($ok ? ' ok' : " FAILED: $detail") . "\n";
    if (!$ok) {
        global $last_html;
        if (!empty($last_html)) {
            file_put_contents('/tmp/install-failure.html', $last_html);
            echo "    (page saved to /tmp/install-failure.html, " .
                 strlen($last_html) . " bytes)\n";
            if (preg_match_all('/class="messages[^"]*"[^>]*>(.*?)<\/div>/s',
                               $last_html, $mm)) {
                foreach ($mm[1] as $msg) {
                    $t = trim(preg_replace('/\s+/', ' ',
                             strip_tags(str_replace('&nbsp;', ' ', $msg))));
                    if ($t !== '') {
                        echo "    message: " . substr($t, 0, 500) . "\n";
                    }
                }
            }
            if (preg_match('/<h1[^>]*>(.*?)<\/h1>/s', $last_html, $h1)) {
                echo "    h1: " . trim(strip_tags($h1[1])) . "\n";
            }
        }
        global $trace, $last_content, $last_url;
        echo "    posted: $last_url = " . substr($last_content, 0, 300) . "\n";
        foreach ($trace as $t) {
            echo "    trace: $t\n";
        }
        exit(1);
    }
}

// Already installed? The front page carries the site name we set.
list($home,) = fetch('/');
if (strpos($home, $SITE_NAME) !== false) {
    echo "[install] already installed\n";
    exit(0);
}

// 1) language (fetch the form directly: a bare GET / answers with an
//    empty-bodied 302, and filling THAT would drop form_build_id)
list($html,) = fetch('/');
list($html,) = fetch('/core/install.php');
list($html,) = fetch('/core/install.php', fill($html, array(
    'langcode' => 'en', 'op' => 'Save and continue')));
step('language', strpos(page_title($html), 'profile') !== false,
     page_title($html));

// 2) profile
list($html,) = fetch('/core/install.php?rewrite=ok&langcode=en',
                     fill($html, array('profile' => 'standard',
                                       'op' => 'Save and continue')));
step('profile', strpos(page_title($html), 'Database configuration') !== false,
     page_title($html));

// 3) database (SQLite) -> the profile-modules batch page
list($html,) = fetch('/core/install.php?rewrite=ok&langcode=en&profile=standard',
                     fill($html, array(
                         'driver' => $SQLITE_DRIVER,
                         $SQLITE_DRIVER . '[database]' => $SQLITE,
                         $SQLITE_DRIVER . '[prefix]' => '',
                         'op' => 'Save and continue')));
step('database', strpos(page_title($html), 'Installing Drupal') !== false,
     page_title($html));
if (!preg_match('/"uri":"([^"]+)"/', $html, $m)) {
    step('batch uri', false, 'no Drupal.settings batch on the page');
}
$uri = json_decode('"' . $m[1] . '"');

// 4) batch: the same protocol batch.js speaks (measure: one process,
//    one cookie session - the batch is bound to it)
$done = false;
for ($i = 0; $i < 80; $i++) {
    list($body,) = fetch($uri . '&op=do', array());
    $json = json_decode($body, true);
    if (!is_array($json)) {
        step('batch poll', false, 'non-JSON (' . strlen($body) . 'B): ' .
             substr(preg_replace('/\s+/', ' ', $body), 0, 200));
    }
    // D10's batch.js protocol: the poll reports progress, and the
    // CLIENT switches to op=finished at 100% (the status never
    // becomes "finished" - measured: percentage 42 -> 66 -> 95 -> 100
    // and then endless status:true).
    if (($json['status'] ?? '') === 'finished' ||
        (int) ($json['percentage'] ?? 0) >= 100) {
        $done = true;
        break;
    }
    if (($json['status'] ?? '') === 'error') {
        step('batch', false, $body);
    }
}
step('batch polls', $done, 'no finished status');
list($html,) = fetch($uri . '&op=finished');
step('configure page', strpos(page_title($html), 'Configure site') !== false,
     page_title($html));

// 5) site configuration (redirects to the finished front page)
list($html,) = fetch('/core/install.php?rewrite=ok&langcode=en&profile=standard',
                     fill($html, array(
                         'site_name' => $SITE_NAME,
                         'site_mail' => 'lab@example.com',
                         'account[name]' => 'admin',
                         'account[mail]' => 'admin@example.com',
                         'account[pass][pass1]' => 'LabPass123456!',
                         'account[pass][pass2]' => 'LabPass123456!',
                         'op' => 'Save and continue')));
$installed = strpos($html, $SITE_NAME) !== false ||
             strpos($html, 'Congratulations') !== false;
step('install complete', $installed, page_title($html));

// 6) the site must serve with its name
list($home,) = fetch('/');
step('front page', strpos($home, $SITE_NAME) !== false, page_title($home));
echo "[install] done\n";
