<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2012 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 * @package   Zend_OAuth
 */

namespace ZendOAuthTest;

use ZendOAuth\Consumer;
use ZendOAuth\Http;
use ZendOAuth\OAuth;
use ZendOAuth\Token;

/**
 * @category   Zend
 * @package    Zend_OAuth
 * @subpackage UnitTests
 * @group      Zend_OAuth
 */
class ConsumerTest extends \PHPUnit_Framework_TestCase
{

    public function teardown()
    {
        OAuth::clearHttpClient();
    }

    public function testConstructorSetsConsumerKey()
    {
        $config = array('consumerKey'=>'1234567890');
        $consumer = new Consumer($config);
        $this->assertEquals('1234567890', $consumer->getConsumerKey());
    }

    public function testConstructorSetsConsumerSecret()
    {
        $config = array('consumerSecret'=>'0987654321');
        $consumer = new Consumer($config);
        $this->assertEquals('0987654321', $consumer->getConsumerSecret());
    }

    public function testSetsSignatureMethodFromOptionsArray()
    {
        $options = array(
            'signatureMethod' => 'rsa-sha1'
        );
        $consumer = new Consumer($options);
        $this->assertEquals('RSA-SHA1', $consumer->getSignatureMethod());
    }

    public function testSetsRequestMethodFromOptionsArray() // add back
    {
        $options = array(
            'requestMethod' => OAuth::GET
        );
        $consumer = new Consumer($options);
        $this->assertEquals(OAuth::GET, $consumer->getRequestMethod());
    }

    public function testSetsRequestSchemeFromOptionsArray()
    {
        $options = array(
            'requestScheme' => OAuth::REQUEST_SCHEME_POSTBODY
        );
        $consumer = new Consumer($options);
        $this->assertEquals(OAuth::REQUEST_SCHEME_POSTBODY, $consumer->getRequestScheme());
    }

    public function testSetsVersionFromOptionsArray()
    {
        $options = array(
            'version' => '1.1'
        );
        $consumer = new Consumer($options);
        $this->assertEquals('1.1', $consumer->getVersion());
    }

    public function testSetsCallbackUrlFromOptionsArray()
    {
        $options = array(
            'callbackUrl' => 'http://www.example.com/local'
        );
        $consumer = new Consumer($options);
        $this->assertEquals('http://www.example.com/local', $consumer->getCallbackUrl());
    }

    public function testSetsRequestTokenUrlFromOptionsArray()
    {
        $options = array(
            'requestTokenUrl' => 'http://www.example.com/request'
        );
        $consumer = new Consumer($options);
        $this->assertEquals('http://www.example.com/request', $consumer->getRequestTokenUrl());
    }

    public function testSetsUserAuthorizationUrlFromOptionsArray()
    {
        $options = array(
            'userAuthorizationUrl' => 'http://www.example.com/authorize'
        );
        $consumer = new Consumer($options);
        $this->assertEquals('http://www.example.com/authorize', $consumer->getUserAuthorizationUrl());
    }

    public function testSetsAccessTokenUrlFromOptionsArray()
    {
        $options = array(
            'accessTokenUrl' => 'http://www.example.com/access'
        );
        $consumer = new Consumer($options);
        $this->assertEquals('http://www.example.com/access', $consumer->getAccessTokenUrl());
    }

    public function testSetSignatureMethodThrowsExceptionForInvalidMethod()
    {
        $config = array('consumerKey'=>'12345','consumerSecret'=>'54321');
        $consumer = new Consumer($config);

        $this->setExpectedException('ZendOAuth\Exception\ExceptionInterface');
        $consumer->setSignatureMethod('buckyball');
    }

    public function testSetRequestMethodThrowsExceptionForInvalidMethod()
    {
        $config = array('consumerKey'=>'12345','consumerSecret'=>'54321');
        $consumer = new Consumer($config);

        $this->setExpectedException('ZendOAuth\Exception\ExceptionInterface');
        $consumer->setRequestMethod('buckyball');
    }

    public function testSetRequestSchemeThrowsExceptionForInvalidMethod()
    {
        $config = array('consumerKey'=>'12345','consumerSecret'=>'54321');
        $consumer = new Consumer($config);

        $this->setExpectedException('ZendOAuth\Exception\ExceptionInterface');
        $consumer->setRequestScheme('buckyball');
    }

    public function testSetLocalUrlThrowsExceptionForInvalidUrl()
    {
        $config = array('consumerKey'=>'12345','consumerSecret'=>'54321');
        $consumer = new Consumer($config);

        $this->setExpectedException('ZendOAuth\Exception\ExceptionInterface');
        $consumer->setLocalUrl('buckyball');
    }

    public function testSetRequestTokenUrlThrowsExceptionForInvalidUrl()
    {
        $config = array('consumerKey'=>'12345','consumerSecret'=>'54321');
        $consumer = new Consumer($config);

        $this->setExpectedException('ZendOAuth\Exception\ExceptionInterface');
        $consumer->setRequestTokenUrl('buckyball');
    }

    public function testSetUserAuthorizationUrlThrowsExceptionForInvalidUrl()
    {
        $config = array('consumerKey'=>'12345','consumerSecret'=>'54321');
        $consumer = new Consumer($config);

        $this->setExpectedException('ZendOAuth\Exception\ExceptionInterface');
        $consumer->setUserAuthorizationUrl('buckyball');
    }

    public function testSetAccessTokenUrlThrowsExceptionForInvalidUrl()
    {
        $config = array('consumerKey'=>'12345','consumerSecret'=>'54321');
        $consumer = new Consumer($config);

        $this->setExpectedException('ZendOAuth\Exception\ExceptionInterface');
        $consumer->setAccessTokenUrl('buckyball');
    }

    public function testGetRequestTokenReturnsInstanceOfOauthTokenRequest()
    {
        $config = array('consumerKey'=>'12345','consumerSecret'=>'54321');
        $consumer = new Consumer($config);
        $token = $consumer->getRequestToken(null, null, new RequestToken48231);
        $this->assertInstanceOf('ZendOAuth\Token\Request', $token);
    }

    public function testGetRedirectUrlReturnsUserAuthorizationUrlWithParameters()
    {
        $config = array('consumerKey'=>'12345','consumerSecret'=>'54321',
            'userAuthorizationUrl'=>'http://www.example.com/authorize');
        $consumer = new Consumer48231($config);
        $params = array('foo'=>'bar');
        $uauth = new Http\UserAuthorization($consumer, $params);
        $token = new Token\Request;
        $token->setParams(array('oauth_token'=>'123456', 'oauth_token_secret'=>'654321'));
        $redirectUrl = $consumer->getRedirectUrl($params, $token, $uauth);
        $this->assertEquals(
            'http://www.example.com/authorize?oauth_token=123456&oauth_callback=http%3A%2F%2Fwww.example.com%2Flocal&foo=bar',
            $redirectUrl
        );
    }

    public function testGetAccessTokenReturnsInstanceOfOauthTokenAccess()
    {
        $config = array('consumerKey'=>'12345','consumerSecret'=>'54321');
        $consumer = new Consumer($config);
        $rtoken = new Token\Request;
        $rtoken->setToken('token');
        $token = $consumer->getAccessToken(array('oauth_token'=>'token'), $rtoken, null, new AccessToken48231);
        $this->assertInstanceOf('ZendOAuth\Token\Access', $token);
    }

    public function testGetLastRequestTokenReturnsInstanceWhenExists()
    {
        $config = array('consumerKey'=>'12345','consumerSecret'=>'54321');
        $consumer = new Consumer48231($config);
        $this->assertInstanceOf('ZendOAuth\Token\Request', $consumer->getLastRequestToken());
    }

    public function testGetLastAccessTokenReturnsInstanceWhenExists()
    {
        $config = array('consumerKey'=>'12345','consumerSecret'=>'54321');
        $consumer = new Consumer48231($config);
        $this->assertInstanceOf('ZendOAuth\Token\Access', $consumer->getLastAccessToken());
    }

}

class RequestToken48231 extends Http\RequestToken
{
    public function __construct(){}
    public function execute(array $params = null)
    {
        $return = new Token\Request;
        return $return;}
    public function setParams(array $customServiceParameters){}
}

class AccessToken48231 extends Http\AccessToken
{
    public function __construct(){}
    public function execute(array $params = null)
    {
        $return = new Token\Access;
        return $return;}
    public function setParams(array $customServiceParameters){}
}

class Consumer48231 extends Consumer
{
    public function __construct(array $options = array())
    {
        $this->_requestToken = new Token\Request;
        $this->_accessToken = new Token\Access;
        parent::__construct($options);}
    public function getCallbackUrl()
    {
        return 'http://www.example.com/local';}
}
