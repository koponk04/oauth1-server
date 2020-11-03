<?php
namespace JoakimKejser\OAuth\Exception;

use JoakimKejser\OAuth\Exception;

class InvalidSignatureException extends Exception
{
	/**
	 * @var string
	 */
	protected $debugInfo;

	/**
	 * @param $debugInfo
	 */
	public function setDebugInfo($debugInfo): void
	{
		$this->debugInfo = $debugInfo;
	}

	/**
	 * @return string
	 */
	public function getDebugInfo()
	{
		return $this->debugInfo;
	}
}
