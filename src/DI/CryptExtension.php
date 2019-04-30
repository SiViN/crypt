<?php declare(strict_types = 1);

namespace SiViN\Crypt\DI;

use Nette\DI\CompilerExtension;
use SiViN\Crypt\Crypt;

class CryptExtension extends CompilerExtension
{
	
	const CONFIG_PUBLIC_KEY_PATH = 'publicKeyPath';
	
	const CONFIG_PRIVATE_KEY_PATH = 'privateKeyPath';
	
	const CONFIG_PRIVATE_KEY_PASSWORD = 'privateKeyPassword';
	
	private $defaults = [
		self::CONFIG_PUBLIC_KEY_PATH => null,
		self::CONFIG_PRIVATE_KEY_PATH => null,
		self::CONFIG_PRIVATE_KEY_PASSWORD => null
	];
	
	public function loadConfiguration()
	{
		$builder = $this->getContainerBuilder();
		$config = $this->validateConfig($this->defaults, $this->config);
		
		$builder->addDefinition($this->prefix('crypt'))
			->setFactory(Crypt::class, ['config' => $config]);
	}
	
}
