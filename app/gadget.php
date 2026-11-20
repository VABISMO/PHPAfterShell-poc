<?php
/**
 * Representative application gadget for the PHPAfterShell PoC.
 *
 * The vulnerability itself (CVE-2026-126714) injects an arbitrary object
 * into $_SESSION with no application cooperation. Turning deserialization
 * into code execution requires a class with a useful magic method - a
 * "gadget". This FileCache mirrors a very common real-world pattern:
 * buffered loggers/caches that flush to disk in __destruct().
 *
 * Chained with the session object injection it yields arbitrary file write,
 * which the exploit uses to drop a webshell in the web root -> RCE.
 */
class FileCache
{
    /** @var string destination path */
    public $path;

    /** @var string content flushed on destruction */
    public $content;

    public function __destruct()
    {
        if (is_string($this->path) && is_string($this->content)) {
            @file_put_contents($this->path, $this->content);
        }
    }
}
