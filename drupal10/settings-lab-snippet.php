// Lab entry: the session-using component of this target (the same two
// behaviours a real cart/auth-bridge package provides). It is appended
// to settings.php AFTER the stock installer writes it - settings.php
// is the file Drupal itself auto-loads on every request (its
// mu-plugin equivalent).
//
// The session is STARTED (native files handler: the only storage the
// session splice can reach), used for this request - one
// user-submitted field is stored in it - and then CLOSED IMMEDIATELY.
// That last step is the measured crux: with the session still open,
// Drupal's own Symfony session service rebuilds $_SESSION from its
// database handler later in the request and empties/destroys the file
// session (measured: PHPSESSID=deleted, the carrier's progress record
// zeroed). Flushing our sid's file up-front freezes it: the rest of
// the request runs its own separate session, and the consumer's
// session_start() still materialises the planted object at decode
// time (its destructor fires at shutdown regardless).
//
// Nothing here reports, diagnoses or exempts anything: the exploit
// still learns only from natural HTTP.
if (PHP_SAPI !== 'cli' && session_status() === PHP_SESSION_NONE && !headers_sent()) {
    session_start();
    if (isset($_REQUEST['bio']) && session_status() === PHP_SESSION_ACTIVE) {
        $_SESSION['bio'] = (string) $_REQUEST['bio'];
    }
    session_write_close();
}
