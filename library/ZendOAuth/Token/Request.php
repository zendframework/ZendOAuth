<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2012 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 * @package   Zend_OAuth
 */

namespace ZendOAuth\Token;

use Zend\Http\Response as HTTPResponse;
use ZendOAuth\Client;
use ZendOAuth\Http\Utility as HTTPUtility;

/**
 * @category   Zend
 * @package    Zend_OAuth
 */
class Request extends AbstractToken
{
    /**
     * Constructor
     *
     * @param null|Zend\Http\Response $response
     * @param null|ZendOAuth\Http\Utility $utility
     */
    public function __construct(
        HTTPResponse $response = null,
        HTTPUtility $utility = null
    ) {
        parent::__construct($response, $utility);

        // detect if server supports OAuth 1.0a
        if (isset($this->_params[AbstractToken::TOKEN_PARAM_CALLBACK_CONFIRMED])) {
            Client::$supportsRevisionA = true;
        }
    }
}
