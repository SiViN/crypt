<?php declare(strict_types = 1);

use Ninjify\Nunjuck\Environment;
use Tracy\Debugger;

if (@!include __DIR__ . '/../vendor/autoload.php') {
    echo 'Install Nette Tester using `composer install`';
    exit(1);
}

Environment::setup(__DIR__);
Debugger::$logDirectory = TEMP_DIR;
