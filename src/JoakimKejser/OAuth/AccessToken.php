<?php
namespace JoakimKejser\OAuth;

/**
 * Class AccessToken
 * @package JoakimKejser\OAuth
 */
class AccessToken implements TokenInterface
{
    /**
     * @var
     */
    protected $key;

    /**
     * @var
     */
    protected $secret;

    function __construct($key, $secret)
    {
        $this->key = $key;
        $this->secret = $secret;
    }

    /**
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * @return string
     */
    public function getSecret()
    {
        return $this->secret;
    }
}
