<?php
/**
 * Lab session plugin for the phpAfterShell WordPress target.
 *
 * Represents the very common class of WordPress plugins that use NATIVE
 * PHP sessions: it starts a session on init and stores one user-submitted
 * field in it, the way a form plugin does. It provides no endpoint, no
 * report and no diagnostic - the exploit still learns only from natural
 * HTTP behaviour, exactly as against any other target.
 *
 * WP-CLI must not start sessions (installer runs under CLI).
 */
add_action('init', function () {
    if (defined('WP_CLI') && WP_CLI) {
        return;
    }
    if (session_status() === PHP_SESSION_NONE && !headers_sent()) {
        session_start();
    }
    if (isset($_POST['bio'])) {
        $_SESSION['bio'] = (string) $_POST['bio'];
    }
}, 0);
