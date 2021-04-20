<?php declare(strict_types = 1);

namespace SiViN\Crypt;

use Exception;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\Random;
use phpseclib3\Crypt\Rijndael;
use phpseclib3\Crypt\RSA;
use SiViN\Crypt\DI\CryptExtension;
use SiViN\Crypt\Exception\DecryptException;
use SiViN\Crypt\Exception\KeyNotFoundException;
use SiViN\Crypt\Exception\WrongKeyException;
use Throwable;

class Crypt
{
	
	/** @var string */
	private $publicKey = null;
	
	/** @var string */
	private $privateKey = null;
	
	/** @var string */
	private $privateKeyPassword;

	/** @var RSA */
	private $rsa;
	
	/** @var string */
	private $lastKeyHash;

	/**
	 * Crypt constructor.
	 *
	 * @param array $config
	 */
	public function __construct(array $config)
	{
		$publicKeyPath = $config[CryptExtension::CONFIG_PUBLIC_KEY_PATH];
		if (empty($publicKeyPath) === false && is_file($publicKeyPath)) {
			$this->publicKey = file_get_contents($publicKeyPath);
		}
		
		$privateKeyPath = $config[CryptExtension::CONFIG_PRIVATE_KEY_PATH];
		if (empty($privateKeyPath) === false && is_file($privateKeyPath)) {
			$this->privateKey = file_get_contents($privateKeyPath);
		}
		
		$this->privateKeyPassword = $config[CryptExtension::CONFIG_PRIVATE_KEY_PASSWORD];
		if (empty($this->privateKeyPassword) === true) {
            $this->privateKeyPassword = false;
        }
		$this->lastKeyHash = '';
	}
	
	/**
	 * @param string|null $password
	 * @param string $privateKeyFormat
	 * @param string $publicKeyFormat
	 * @param int $bits
	 *
	 * @return array
	 */
	public function createKeyPair(string $password = null, string $privateKeyFormat = 'PKCS1',
	                              string $publicKeyFormat = 'PKCS8', int $bits = 1024)
	{
		$privateKey = RSA::createKey($bits);
        if (empty($password) === false) {
            $privateKey = $privateKey->withPassword($password);
        }
        /** @var RSA\PublicKey $publicKey */
        $publicKey = $privateKey->getPublicKey();

		return ['privateKeyRaw' =>  $privateKey->toString($privateKeyFormat), 'publicKeyRaw' => $publicKey->toString($publicKeyFormat)];
	}
	
	/**
	 * @param string $encodedSymmetricKey
	 * @param string $cipherStr
	 *
	 * @return string
	 */
	public function generateTransportMessage(string $encodedSymmetricKey, string $cipherStr)
	{
		$encodedSymmetricKey = base64_encode($encodedSymmetricKey);
		$lenKey = dechex(strlen($encodedSymmetricKey));
		$lenKey = str_pad($lenKey, 3, '0', STR_PAD_LEFT);
		
		return $lenKey . $encodedSymmetricKey . $cipherStr;
	}
	
	/**
	 * @param string $str
	 * @param string $mode
	 * @param int $symmetricKeyLength
	 *
	 * @return string
	 * @throws KeyNotFoundException
	 * @throws WrongKeyException
	 */
	public function encryptRijndaelMessage(string $str, string $mode = 'ecb', int $symmetricKeyLength = 32)
	{
		$symKey = $this->generateSymmetricKey($symmetricKeyLength);
		$encSymKey = $this->encryptRsa($symKey);
		$encSymKey = base64_encode($encSymKey);
		$lenSymKey = strlen($encSymKey);
		$lenSymKey = dechex($lenSymKey);
		$lenSymKey = str_pad($lenSymKey, 3, '0', STR_PAD_LEFT);
		
		$encRij = $this->encryptRijndael($symKey, $str, $mode);
		$encRij = base64_encode($encRij);
		
		return $lenSymKey . $encSymKey . $encRij;
	}
	
	/**
	 * @param int $length
	 *
	 * @return string
	 */
	public function generateSymmetricKey(int $length = 32): string
	{
		return Random::string($length);
	}
	
	/**
	 * @param string $str
	 *
	 * @return string
	 * @throws KeyNotFoundException
	 * @throws WrongKeyException
	 */
	public function encryptRsa(string $str)
	{
		$this->loadKey($this->publicKey);
		$cipherStr = $this->rsa->withPadding(RSA\PublicKey::ENCRYPTION_PKCS1)->encrypt($str);
		return $cipherStr;
	}
	
	/**
	 * @param $key
	 *
	 * @return bool
	 * @throws KeyNotFoundException
	 * @throws WrongKeyException
	 */
	private function loadKey($key): bool
	{
		$keyHash = md5($key);
		if (strcmp($this->lastKeyHash, $keyHash) === 0) {
			return true;
		}
		
		$this->validateKey($key);

        try {
            $this->rsa = PublicKeyLoader::load($key, $this->privateKeyPassword);
            $this->lastKeyHash = $keyHash;
        }
		catch (Throwable $e) {
            throw new WrongKeyException('The key has unknown type or the password is wrong', 0, $e);
        }

		return true;
	}
	
	/**
	 * @param string $key
	 *
	 * @param bool $throw
	 *
	 * @return bool
	 * @throws KeyNotFoundException
	 */
	private function validateKey($key, bool $throw = true): bool
	{
		if (empty($key)) {
			if ($throw) {
				throw new KeyNotFoundException("Missing key");
			}
			return false;
		}
		
		return true;
	}

    /**
     * @param string $symmetricKey
     * @param string $str
     * @param string $mode
     *
     * @return string
     * @throws WrongKeyException
     */
	public function encryptRijndael(string $symmetricKey, string $str, string $mode = 'ecb')
	{
        try {
            $rij = new Rijndael($mode);
            $rij->setKey($symmetricKey);

            $cipherStr = $rij->encrypt($str);
        }
        catch (Exception $e) {
            throw new WrongKeyException("", 0, $e);
        }

		return $cipherStr;
	}
	
	/**
	 * @param string $message
	 * @param string $mode
	 *
	 * @return string|null
	 * @throws KeyNotFoundException
	 * @throws WrongKeyException
	 * @throws DecryptException
	 */
	public function decryptRijndaelMessage(string $message, string $mode = 'ecb')
	{
		if (empty($message) === true) {
			throw new DecryptException('The message is not valid');
		}
		
		$lenSymKey = substr($message, 0, 3);
		$lenSymKey = hexdec($lenSymKey);
		$encSymKey = substr($message, 3, $lenSymKey);
		$encSymKey = base64_decode($encSymKey);
		
		$symKey = $this->decryptRsa($encSymKey);
		
		$message = substr($message, 3);
		$cipherStr = substr($message, $lenSymKey);
		$cipherStr = base64_decode($cipherStr);
		
		$str = $this->decryptRijndael($symKey, $cipherStr, $mode);
		return $str;
	}
	
	/**
	 * @param string $cipherStr
	 *
	 * @return string
	 * @throws KeyNotFoundException
	 * @throws WrongKeyException
	 * @throws DecryptException
	 */
	public function decryptRsa(string $cipherStr): string
	{
		$this->loadKey($this->privateKey);
		$res = $this->rsa->withPadding(RSA\PublicKey::ENCRYPTION_PKCS1)->decrypt($cipherStr);
		if (is_string($res)) {
			return $res;
		}
		throw new DecryptException('The cipher cannot be decrypted');
	}

    /**
     * @param string $symmetricKey
     * @param string $cipherStr
     * @param string $mode
     *
     * @return string
     * @throws WrongKeyException
     */
	public function decryptRijndael(string $symmetricKey, string $cipherStr, string $mode = 'ecb')
	{
		$rij = new Rijndael($mode);

        try {
            $rij->setKey($symmetricKey);
            $str = $rij->decrypt($cipherStr);
            if ($str === false) {
                throw new WrongKeyException();
            }
        }
        catch (Exception $e) {
            throw new WrongKeyException("", 0, $e);
        }

		return $str;
	}
	
	/**
	 * @param string $publicKey
	 */
	public function setPublicKey($publicKey)
	{
		$this->publicKey = $publicKey;
		$this->lastKeyHash = '';
	}
	
	/**
	 * @param string $privateKey
	 */
	public function setPrivateKey($privateKey)
	{
		$this->privateKey = $privateKey;
		$this->lastKeyHash = '';
	}
	
	/**
	 * @param string $privateKeyPassword
	 */
	public function setPrivateKeyPassword(string $privateKeyPassword)
	{
		$this->privateKeyPassword = $privateKeyPassword;
		$this->lastKeyHash = '';
	}
	
	/**
	 * @return bool
	 * @throws KeyNotFoundException
	 */
	public function hasDefinedPublicKey(): bool
	{
		return $this->validateKey($this->publicKey, false);
	}
	
	/**
	 * @return bool
	 * @throws KeyNotFoundException
	 */
	public function hasDefinedPrivateKey(): bool
	{
		return $this->validateKey($this->privateKey, false);
	}
	
}
