<?php
namespace app\middleware;

/**
 * Lab component for the phpAfterShell ThinkPHP target: the
 * session-using entry point (the same behaviour a cart / SSO-bridge
 * integration provides). ThinkPHP's own think\session\Store never
 * touches PHP's native session module, so a native session runs
 * independently: it starts one (files handler) and stores one
 * user-submitted field. No endpoint, no report, no diagnostic: the
 * exploit still learns only from natural HTTP behaviour.
 */
class NativeSession
{
    public function handle($request, \Closure $next)
    {
        if (session_status() === PHP_SESSION_NONE && !headers_sent()) {
            session_start();
        }
        if (isset($_REQUEST['bio']) && session_status() === PHP_SESSION_ACTIVE) {
            $_SESSION['bio'] = (string) $_REQUEST['bio'];
        }
        return $next($request);
    }
}
