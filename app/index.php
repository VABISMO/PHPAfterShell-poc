<?php
/**
 * Demo target application for the PHPAfterShell lab.
 *
 * Deliberately boring: this is what a normal application looks like to the
 * exploit - it starts a session and shows a page. There is NO diagnostic
 * endpoint, NO state dump and NO helper route; the exploit has to work
 * from natural signals only (HTTP behaviour + the webshell it drops).
 *
 * - POST bio=<bytes>   : ordinary app feature - stores user input in the
 *                        session (this is the carrier record's payload).
 * - GET                 : any page that calls session_start() is enough for
 *                        the attacker: the injected object materialises on
 *                        decode and flushes its gadget on shutdown.
 */
require_once __DIR__ . '/gadget.php';   // the class must exist before the
                                        // session decoder runs
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && array_key_exists('bio', $_POST)) {
    $_SESSION['bio'] = (string) $_POST['bio'];
    header('Content-Type: text/plain');
    echo 'stored:' . strlen($_SESSION['bio']);
    exit;
}

header('Content-Type: text/plain');
echo "welcome\n";
