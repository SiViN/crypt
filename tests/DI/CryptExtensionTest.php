<?php /** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace SiViN\Crypt\Tests\DI;

use SiViN\Crypt\Crypt;
use SiViN\Crypt\Tests\Fixtures\BaseTestCase;
use Tester\Assert;

require_once __DIR__ . '/../bootstrap.php';

class CryptExtensionTest extends BaseTestCase
{

	public function testExtension()
	{
		$dic = $this->buildDic();
		Assert::type('Nette\DI\Container', $dic);
		
		/** @var Crypt $service */
		$service = $dic->getByType(Crypt::class);
		
		Assert::type(Crypt::class, $service);
		
		$rsaService = $this->getCryptService();
		Assert::type(Crypt::class, $rsaService);
	}
	
}

(new CryptExtensionTest())->run();
