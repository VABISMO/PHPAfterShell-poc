
// Lab entry: the session-using component of this target (the same two
// behaviours a real cart/auth-bridge package provides). It lives in
// settings.php - the file Drupal itself auto-loads on every request:
//
// 1. start a native PHP session (files handler) BEFORE Drupal installs
//    its own save handler - a common settings.php snippet for
//    integrations that need $_SESSION during bootstrap. Drupal normally
//    loads $user inside its own DB session read; with the native handler
//    taking over that read never runs, so provide the same anonymous
//    user object Drupal itself would have loaded;
// 2. store one user-submitted field in the session (ordinary form ->
//    session behaviour). Nothing here reports, diagnoses or exempts
//    anything: the exploit still learns only from natural HTTP.
// Standard production setting (Configuration > Development > Error
// reporting = "Hide errors from the screen"): with the native session
// active, Drupal's own session_name/session_set_save_handler/session_id
// calls warn on every request - a real site hides those from visitors
// (and so does this target; the exploit never depends on error output).
$conf["error_level"] = 0;

if (PHP_SAPI !== "cli" && session_status() === PHP_SESSION_NONE && !headers_sent()) {
  session_start();
  // Drupal normally loads $user inside its own DB session read; with
  // the native handler taking over that read never runs, so provide
  // the same anonymous user object Drupal itself would have loaded.
  // Skipped while Drupal's own installer runs: its early tasks execute
  // before the database is loaded and user_role_permissions() would
  // query it (measured fatal on install.php: db_query undefined).
  global $user;
  if (!isset($user) && basename($_SERVER["SCRIPT_NAME"] ?? "") !== "install.php") {
    $user = drupal_anonymous_user();
  }
}
if (isset($_REQUEST["bio"]) && session_status() === PHP_SESSION_ACTIVE) {
  $_SESSION["bio"] = (string) $_REQUEST["bio"];
}
