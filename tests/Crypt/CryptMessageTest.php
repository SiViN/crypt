<?php /** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace SiViN\Crypt\Tests\Crypt;

use SiViN\Crypt\Tests\Fixtures\BaseTestCase;
use Tester\Assert;

require_once __DIR__ . '/../bootstrap.php';

class CryptMessageTest extends BaseTestCase
{
	
	private $str = 'Lorem ipsum dolor sit amet, consectetuer adipiscing elit. In enim a arcu imperdiet malesuada.';
	
	public function testCompleteTransport()
	{
		$crypt = $this->getCryptService();
		$keys = $crypt->createKeyPair();
		$crypt->setPublicKey($keys['publicKeyRaw']);
		$crypt->setPrivateKey($keys['privateKeyRaw']);
		
		$messageEnc = $crypt->encryptRijndaelMessage($this->str);
		$str = $crypt->decryptRijndaelMessage($messageEnc);
		Assert::equal($str, $this->str);
	}

}

(new CryptMessageTest())->run();
