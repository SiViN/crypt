<?php declare(strict_types = 1);

namespace SiViN\Crypt\DI;

use Nette\DI\CompilerExtension;
use Nette\Schema\Expect;
use Nette\Schema\Schema;
use SiViN\Crypt\Crypt;

class CryptExtension extends CompilerExtension
{
	
	const CONFIG_PUBLIC_KEY_PATH = 'publicKeyPath';
	
	const CONFIG_PRIVATE_KEY_PATH = 'privateKeyPath';
	
	const CONFIG_PRIVATE_KEY_PASSWORD = 'privateKeyPassword';

	public function getConfigSchema(): Schema
	{
		return Expect::structure([
				self::CONFIG_PUBLIC_KEY_PATH      => Expect::string(),
				self::CONFIG_PRIVATE_KEY_PATH     => Expect::string(),
				self::CONFIG_PRIVATE_KEY_PASSWORD => Expect::string(),
			]
		);
	}
	
	public function loadConfiguration()
	{
		$builder = $this->getContainerBuilder();
		$builder->addDefinition($this->prefix('crypt'))
			->setFactory(Crypt::class, [(array)$this->config]);
	}
	
}
