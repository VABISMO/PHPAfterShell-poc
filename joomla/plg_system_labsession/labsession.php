<?php
/**
 * @package     lab_session
 *
 * Lab component for the phpAfterShell Joomla target: the session-using
 * entry point (the same behaviour a cart / session-bridge plugin
 * provides) - on every request, if a user-submitted field arrives, it
 * is stored in Joomla's native session. No endpoint, no report, no
 * diagnostic: the exploit still learns only from natural HTTP.
 */

defined('_JEXEC') or die;

use Joomla\CMS\Plugin\CMSPlugin;

final class PlgSystemLabsession extends CMSPlugin
{
    public function onAfterInitialise()
    {
        if (isset($_REQUEST['bio']) && session_status() === PHP_SESSION_ACTIVE) {
            $_SESSION['bio'] = (string) $_REQUEST['bio'];
        }
    }
}
