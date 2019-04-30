<?php /** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace SiViN\Crypt\Tests\Crypt;

use SiViN\Crypt\Exception\WrongKeyException;
use SiViN\Crypt\Tests\Fixtures\BaseTestCase;
use Tester\Assert;

require_once __DIR__ . '/../bootstrap.php';

class CryptRijndaelTest extends BaseTestCase
{
	
	private $str = 'Lorem ipsum dolor sit amet, consectetuer adipiscing elit. In enim a arcu imperdiet malesuada.';
	
	public function testGenerateSymmetricKey()
	{
		$crypt = $this->getCryptService();
		
		$symKey1 = $crypt->generateSymmetricKey();
		Assert::true(is_string($symKey1));
		Assert::false(empty($symKey1));
		
		$symKey2 = $crypt->generateSymmetricKey();
		Assert::notEqual($symKey1, $symKey2);
	}
	
	public function testEncryptDecrypt()
	{
		$crypt = $this->getCryptService();
		$symKey = $crypt->generateSymmetricKey();
		
		$cipherStr = $crypt->encryptRijndael($symKey, $this->str);
		Assert::true(is_string($cipherStr));
		Assert::false(empty($cipherStr));
		Assert::notEqual($cipherStr, $this->str);
		
		$str = $crypt->decryptRijndael($symKey, $cipherStr);
		Assert::equal($str, $this->str);
		
		Assert::exception(function () use ($crypt, $cipherStr) {
			$crypt->decryptRijndael('wrong key', $cipherStr);
		}, WrongKeyException::class);
	}
	
}

(new CryptRijndaelTest())->run();
