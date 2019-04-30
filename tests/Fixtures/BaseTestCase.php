<?php declare(strict_types = 1);

namespace SiViN\Crypt\Tests\Fixtures;

use Nette\DI\Compiler;
use Nette\DI\Container;
use Nette\DI\ContainerLoader;
use SiViN\Crypt\Crypt;
use SiViN\Crypt\DI\CryptExtension;
use Tester\TestCase;

class BaseTestCase extends TestCase
{
	
	protected function getCryptService(Container $dic = null): Crypt
	{
		$container = $dic ?? $this->buildDic();
		
		/** @var Crypt $service */
		$service = $container->getByType(Crypt::class);
		
		return $service;
	}
	
	protected function buildDic(): Container
	{
		$loader = new ContainerLoader(TEMP_DIR);
		
		$className = $loader->load(function (Compiler $compiler) {
			$compiler->addExtension('crypt', new CryptExtension());
		});
		
		/** @var Container $dic */
		$dic = new $className();
		return $dic;
	}
	
}
