<?php
/**
 * First-boot installer for the Drupal lab target.
 *
 * Drives Drupal's own web installer over HTTP from inside the
 * container - exactly the requests a browser would send: the form
 * fills, the no-JS batch protocol (op=do polls + op=finished), the
 * site configuration form. No CLI bootstrap, no direct database
 * writes, no helper endpoints: the site is installed the stock way.
 *
 * Idempotent: exits 0 immediately when the site is already installed.
 * Any failure exits non-zero so the container's healthcheck stays red.
 */

$BASE = 'http://127.0.0.1';
$SITE_NAME = 'phpAfterShell lab';
$jar = array();
$trace = array();   // redirect chain of the last fetch (for failures)

function fetch($url, $data = null, $timeout = 300)
{
    global $jar, $BASE, $trace;
    $trace = array();
    if (strpos($url, 'http') !== 0) {
        $url = $BASE . ($url[0] === '/' ? '' : '/') . $url;
    }
    $headers = "Accept: */*\r\n";
    if ($jar) {
        $pairs = array();
        foreach ($jar as $k => $v) {
            $pairs[] = $k . '=' . $v;
        }
        $headers .= 'Cookie: ' . implode('; ', $pairs) . "\r\n";
    }
    $content = ($data === null) ? null : http_build_query($data);
    if ($content !== null) {
        $headers .= "Content-Type: application/x-www-form-urlencoded\r\n";
    }
    // Redirects are followed MANUALLY: PHP's wrapper only exposes the
    // headers of the final response, so a Set-Cookie on an
    // intermediate 302 would be lost - and Drupal's batch token is
    // derived from session_id(), so one dropped cookie makes
    // batch_load() fail with "No active batch." on the next request
    // (measured).
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
                $trace[] = trim($h);
            } elseif (stripos($h, 'location:') === 0) {
                $location = trim(substr($h, 9));
                $trace[] = '-> ' . $location;
            } elseif (stripos($h, 'set-cookie:') === 0) {
                $kv = explode(';', substr($h, 11));
                $pair = explode('=', $kv[0], 2);
                if (count($pair) === 2) {
                    $jar[trim($pair[0])] = trim($pair[1]);
                }
            }
        }
        // refresh the Cookie header for the next hop
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

/** Every form control: hidden + checked radios/checkboxes + text
 *  inputs carrying a value + selects, then the caller's overrides. */
function fill($html, $overrides = array())
{
    $d = array();
    if (preg_match_all('/<input[^>]*>/', $html, $tags)) {
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
            } elseif (($type === 'text' || $type === 'password') && $has_value) {
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
    global $trace;
    echo "[install] $label" . ($ok ? ' ok' : " FAILED: $detail") . "\n";
    if (!$ok) {
        foreach ($trace as $t) {
            echo "    $t\n";
        }
        global $last_html;
        if (!empty($last_html)) {
            file_put_contents('/tmp/install-failure.html', $last_html);
            echo "    (page saved to /tmp/install-failure.html, " .
                 strlen($last_html) . " bytes)\n";
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

// 1) profile
list($html,) = fetch('/install.php');
list($html,) = fetch('/install.php', fill($html, array(
    'profile' => 'standard', 'op' => 'Save and continue')));
step('profile', strpos(page_title($html), 'Choose language') !== false,
     page_title($html));

// 2) language
list($html,) = fetch('/install.php?profile=standard', fill($html, array(
    'locale' => 'en', 'op' => 'Save and continue')));
step('locale', strpos(page_title($html), 'Database configuration') !== false,
     page_title($html));

// 3) database (SQLite - the only driver this PHP supports) + the
//    install_profile_modules batch, driven the way batch.js does:
//    POST uri&op=do until every set is processed, then op=finished.
list($html,) = fetch('/install.php?profile=standard&locale=en', fill($html, array(
    'sqlite[database]' => 'sites/default/files/.ht.sqlite',
    'sqlite[db_prefix]' => '',
    'op' => 'Save and continue')));
if (!preg_match('/jQuery\.extend\(Drupal\.settings, (\{.*?\})\);/s', $html, $m)) {
    step('batch page', false, 'no Drupal.settings on "' . page_title($html) . '"');
}
$settings = json_decode($m[1], true);
$uri = isset($settings['batch']['uri']) ? $settings['batch']['uri'] : '';
step('batch uri', $uri !== '', page_title($html));

$configure = false;
for ($round = 0; $round < 12 && !$configure; $round++) {
    for ($i = 0; $i < 60; $i++) {
        list($body,) = fetch($uri . '&op=do', array());
        $json = json_decode($body, true);
        if (!is_array($json)) {
            global $trace;
            $err = error_get_last();
            // Is the server even reachable right now?
            $probe = @file_get_contents('http://127.0.0.1/install.php',
                false, stream_context_create(array('http' => array(
                    'timeout' => 5, 'follow_location' => 0,
                    'ignore_errors' => true))));
            $probe_ok = ($probe !== false && strlen($probe) > 100);
            step('batch poll', false, 'non-JSON (' . strlen($body) . 'B) ' .
                 'err=[' . ($err ? $err['message'] : '?') . '] ' .
                 'server=' . ($probe_ok ? 'up' : 'DOWN') .
                 ' trace=[' . implode(' | ', $trace) . ']');
        }
        if (isset($json['status']) && $json['status'] === 'finished') {
            break;
        }
        if (isset($json['status']) && $json['status'] === 'error') {
            step('batch', false, $body);
        }
    }
    list($html,) = fetch($uri . '&op=finished');
    $configure = strpos(page_title($html), 'Configure site') !== false;
    if (!$configure) {
        // not done yet: resume from the current install.php state
        list($html,) = fetch('/install.php?profile=standard&locale=en');
        if (preg_match('/jQuery\.extend\(Drupal\.settings, (\{.*?\})\);/s', $html, $m)) {
            $settings = json_decode($m[1], true);
            $uri = isset($settings['batch']['uri']) ? $settings['batch']['uri'] : $uri;
        }
        $configure = strpos(page_title($html), 'Configure site') !== false;
    }
}
step('profile modules', $configure, page_title($html));

// 4) site configuration
list($html,) = fetch('/install.php?profile=standard&locale=en', fill($html, array(
    'site_name' => $SITE_NAME,
    'site_mail' => 'lab@example.com',
    'account[name]' => 'admin',
    'account[mail]' => 'admin@example.com',
    'account[pass][pass1]' => 'LabPass123!',
    'account[pass][pass2]' => 'LabPass123!',
    'op' => 'Save and continue')));
$done = (strpos($html, 'Congratulations') !== false) ||
        (strpos(page_title($html), 'installation complete') !== false);
if (!$done && preg_match('/jQuery\.extend\(Drupal\.settings, (\{.*?\})\);/s', $html, $m)) {
    // a trailing batch (e.g. locale import) - drain it the same way
    $settings = json_decode($m[1], true);
    $uri = isset($settings['batch']['uri']) ? $settings['batch']['uri'] : '';
    for ($i = 0; $i < 60 && !$done; $i++) {
        list($body,) = fetch($uri . '&op=do', array());
        $json = json_decode($body, true);
        if (is_array($json) && isset($json['status']) && $json['status'] === 'error') {
            step('final batch', false, $body);
        }
    }
    list($html,) = fetch($uri . '&op=finished');
    $done = (strpos($html, 'Congratulations') !== false) ||
            (strpos(page_title($html), 'installation complete') !== false);
}
step('configure', $done, page_title($html));

// 5) verify the site actually serves
list($home,) = fetch('/');
step('front page', strpos($home, $SITE_NAME) !== false, page_title($home));
echo "[install] done\n";
