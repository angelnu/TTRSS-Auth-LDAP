<?php

/**
 * Tiny Tiny RSS plugin for LDAP authentication 
 * @author tsmgeek (tsmgeek@gmail.com)
 * @author hydrian (ben.tyger@tygerclan.net)
 * @author angelnu (git@angelnu.com)
 * @copyright GPL2
 *  Requires php-ldap 
 * @version 3.00
 */

/**
 * 	Notes -
 * 	LDAP search does not support follow ldap referals. Referals are disabled to 
 * 	allow proper login.  This is particular to Active Directory.  
 * 
 * 	Also group membership can be supported if the user object contains the
 * 	the group membership via attributes.  The following LDAP servers can 
 * 	support this.   
 * 	 * Active Directory
 *   * OpenLDAP support with MemberOf Overlay
 *
 */
class Auth_Ldap extends Auth_Base {

  	/** LDAP server URI; .env:
     * LDAP_AUTH_SERVER_URI=ldaps://LDAPServerHostname:port/
     */
    const LDAP_AUTH_SERVER_URI = "LDAP_AUTH_SERVER_URI";    
    
    /** LDAP server uses TLS; .env:
     * LDAP_AUTH_USETLS=True
     */
    const LDAP_AUTH_USETLS = "LDAP_AUTH_USETLS";

    /** LDAP allows untrusted certificate; .env:
     * LDAP_AUTH_ALLOW_UNTRUSTED_CERT=True
     */
    const LDAP_AUTH_ALLOW_UNTRUSTED_CERT = "LDAP_AUTH_ALLOW_UNTRUSTED_CERT";

    /** LDAP auth bind DN; .env:
     * LDAP_AUTH_BINDDN='cn=???,ou=users,dc=example,dc=com'
     * ??? will be replaced with the entered username(escaped) at login
     */
    const LDAP_AUTH_BINDDN = "LDAP_AUTH_BINDDN";

    /** LDAP auth bind password; .env:
     * LDAP_AUTH_BINDPW='ServiceAccountsPassword'
     */
    const LDAP_AUTH_BINDPW = "LDAP_AUTH_BINDPW";

    /** LDAP Base DN; .env:
     * LDAP_AUTH_BASEDN='dc=example,dc=com'
     */
    const LDAP_AUTH_BASEDN = "LDAP_AUTH_BASEDN";

    /** LDAP auth searchfilter; .env:
     * LDAP_AUTH_SEARCHFILTER='(&(objectClass=person)(uid=???))'
     * ??? will be replaced with the entered username(escaped) at login
     */
    const LDAP_AUTH_SEARCHFILTER = "LDAP_AUTH_SEARCHFILTER";

    /** LDAP login attribute; .env:
     * LDAP_AUTH_LOGIN_ATTRIB='uid'
     */
    const LDAP_AUTH_LOGIN_ATTRIB = "LDAP_AUTH_LOGIN_ATTRIB";

    /** LDAP full name attribute; .env:
     * LDAP_AUTH_FULLNAME_ATTRIB='name'
     */
    const LDAP_AUTH_FULLNAME_ATTRIB = "LDAP_AUTH_FULLNAME_ATTRIB";

    /** LDAP email attribute; .env:
     * LDAP_AUTH_EMAIL_ATTRIB='mail'
     */
    const LDAP_AUTH_EMAIL_ATTRIB = "LDAP_AUTH_EMAIL_ATTRIB";

    /** LDAP auth debug; .env:
     * LDAP_AUTH_DEBUG=True
     */
    const LDAP_AUTH_DEBUG = "LDAP_AUTH_DEBUG";

    
    private $_debugMode;

    function about() {
        return array(3.00,
            "Authenticates against an LDAP server",
            "angelnu",
            true);
    }

    function init($host) {

        // Required settings
        Config::add(self::LDAP_AUTH_SERVER_URI,           "",     Config::T_STRING);
        // Optional settings
        Config::add(self::LDAP_AUTH_USETLS,               False,  Config::T_BOOL);
        Config::add(self::LDAP_AUTH_ALLOW_UNTRUSTED_CERT, False,  Config::T_BOOL);
        Config::add(self::LDAP_AUTH_BINDDN,               "",     Config::T_STRING);
        Config::add(self::LDAP_AUTH_BINDPW,               "",     Config::T_STRING);
        Config::add(self::LDAP_AUTH_BASEDN,               "",     Config::T_STRING);
        Config::add(self::LDAP_AUTH_SEARCHFILTER,         "",     Config::T_STRING);
        Config::add(self::LDAP_AUTH_LOGIN_ATTRIB,         "",     Config::T_STRING);
        Config::add(self::LDAP_AUTH_FULLNAME_ATTRIB,      "name", Config::T_STRING);
        Config::add(self::LDAP_AUTH_EMAIL_ATTRIB,         "mail", Config::T_STRING);
        Config::add(self::LDAP_AUTH_DEBUG,                False,  Config::T_BOOL);

        // Check required parameters
        if (Config::get(self::LDAP_AUTH_SERVER_URI) == "") {
            Logger::log(E_USER_ERROR, 'Missing ' . self::LDAP_AUTH_SERVER_URI);
            return;
        }
        
        $this->_debugMode = Config::get(self::LDAP_AUTH_DEBUG);
        
        $host->add_hook($host::HOOK_AUTH_USER, $this);
    }

    /**
     * @param string $subject The subject string
     * @param string $ignore Set of characters to leave untouched
     * @param int $flags Any combination of LDAP_ESCAPE_* flags to indicate the
     *                   set(s) of characters to escape.
     * @return string
     **/
    function ldap_escape($subject, $ignore = '', $flags = 0)
    {
        if (!function_exists('ldap_escape')) {
            define('LDAP_ESCAPE_FILTER', 0x01);
            define('LDAP_ESCAPE_DN',     0x02);
            
            static $charMaps = array(
                LDAP_ESCAPE_FILTER => array('\\', '*', '(', ')', "\x00"),
                LDAP_ESCAPE_DN     => array('\\', ',', '=', '+', '<', '>', ';', '"', '#'),
            );

            // Pre-process the char maps on first call
            if (!isset($charMaps[0])) {
                $charMaps[0] = array();
                for ($i = 0; $i < 256; $i++) {
                    $charMaps[0][chr($i)] = sprintf('\\%02x', $i);;
                }

                for ($i = 0, $l = count($charMaps[LDAP_ESCAPE_FILTER]); $i < $l; $i++) {
                    $chr = $charMaps[LDAP_ESCAPE_FILTER][$i];
                    unset($charMaps[LDAP_ESCAPE_FILTER][$i]);
                    $charMaps[LDAP_ESCAPE_FILTER][$chr] = $charMaps[0][$chr];
                }

                for ($i = 0, $l = count($charMaps[LDAP_ESCAPE_DN]); $i < $l; $i++) {
                    $chr = $charMaps[LDAP_ESCAPE_DN][$i];
                    unset($charMaps[LDAP_ESCAPE_DN][$i]);
                    $charMaps[LDAP_ESCAPE_DN][$chr] = $charMaps[0][$chr];
                }
            }

            // Create the base char map to escape
            $flags = (int)$flags;
            $charMap = array();
            if ($flags & LDAP_ESCAPE_FILTER) {
                $charMap += $charMaps[LDAP_ESCAPE_FILTER];
            }
            if ($flags & LDAP_ESCAPE_DN) {
                $charMap += $charMaps[LDAP_ESCAPE_DN];
            }
            if (!$charMap) {
                $charMap = $charMaps[0];
            }

            // Remove any chars to ignore from the list
            $ignore = (string)$ignore;
            for ($i = 0, $l = strlen($ignore); $i < $l; $i++) {
                unset($charMap[$ignore[$i]]);
            }

            // Do the main replacement
            $result = strtr($subject, $charMap);

            // Encode leading/trailing spaces if LDAP_ESCAPE_DN is passed
            if ($flags & LDAP_ESCAPE_DN) {
                if ($result[0] === ' ') {
                    $result = '\\20' . substr($result, 1);
                }
                if ($result[strlen($result) - 1] === ' ') {
                    $result = substr($result, 0, -1) . '\\20';
                }
            }

            return $result;
        }else{
            return ldap_escape($subject, $ignore, $flags);
        }    
    }

    /**
     * Main Authentication method
     * Required for plugin interface 
     * @param string $login  User's username
     * @param string $password User's password
     * @return boolean
     */
    function authenticate($login, $password, $service = '') {
        if (!$login or !$password) {
            return False;
        }

        if (!function_exists('ldap_connect')) {
            Logger::log(E_USER_ERROR, 'auth_ldap requires PHP\'s PECL LDAP package installed.');
            return False;
        }


        /**
             Building LDAP connection
        * */
        
        if ($this->_debugMode)
            Logger::log(E_USER_NOTICE, 'Trying to connect to ' . Config::get(self::LDAP_AUTH_SERVER_URI));

        $ldapConn = @ldap_connect(Config::get(self::LDAP_AUTH_SERVER_URI));
        if ($ldapConn === False) {
            Logger::log(E_USER_ERROR, 'Could not connect to LDAP Server: ' . Config::get(self::LDAP_AUTH_SERVER_URI));
            return false;
        }

        /* Enable LDAP protocol version 3. */
        if (!@ldap_set_option($ldapConn, LDAP_OPT_PROTOCOL_VERSION, 3)) {
            Logger::log(E_USER_ERROR, 'Failed to set LDAP Protocol version (LDAP_OPT_PROTOCOL_VERSION) to 3');
            return false;
        }

        /* Set referral option */
        if (!@ldap_set_option($ldapConn, LDAP_OPT_REFERRALS, False)) {
            Logger::log(E_USER_ERROR, 'Failed to set LDAP Referrals (LDAP_OPT_REFERRALS) to TRUE');
            return false;
        }

        /* Set referral option */
        if (Config::get(self::LDAP_AUTH_ALLOW_UNTRUSTED_CERT)) { 
            if (!@ldap_set_option($ldapConn, LDAP_OPT_X_TLS_REQUIRE_CERT, LDAP_OPT_X_TLS_NEVER)) {
                Logger::log(E_USER_ERROR, 'Failed to set LDAP TLS Cert (LDAP_OPT_X_TLS_REQUIRE_CERT) to LDAP_OPT_X_TLS_NEVER');
                return false;
            }
        }

        if (stripos(Config::get(self::LDAP_AUTH_SERVER_URI), "ldaps:") === False and Config::get(self::LDAP_AUTH_USETLS)) {
            if (!@ldap_start_tls($ldapConn)) {
                Logger::log(E_USER_ERROR, 'Unable to force TLS');
                return false;
            }
        }

        if ($this->_debugMode)
            Logger::log(E_USER_NOTICE, "LDAP connection configured");
        
        
        /**
             Binding
         * */

        // Bind DN
        $serviceBindDN = str_replace('???', $this->ldap_escape($login), Config::get(self::LDAP_AUTH_BINDDN));
        
        // Bind password
        $serviceBindPass = Config::get(self::LDAP_AUTH_BINDPW) != "" ?
            Config::get(self::LDAP_AUTH_BINDPW) : $password;            
        

        if ($this->_debugMode)
            Logger::log(E_USER_NOTICE, 'Trying to bind with ' . $serviceBindDN);
        
        $error = @ldap_bind($ldapConn, $serviceBindDN, $serviceBindPass);
        if ($error === False) {
            Logger::log(E_USER_ERROR, 'LDAP bind(): Bind failed (' . $error . ') with DN ' . $serviceBindDN);
            return False;
        }
        
        if ($this->_debugMode)
            Logger::log(E_USER_NOTICE, 'LDAP bound');
        
        
        /**
             Searching user in Base DN
         * */
        
        if (Config::get(self::LDAP_AUTH_SEARCHFILTER) == "") {
            
            // If no search filter then we are done (binding enough)            
            if ($this->_debugMode)
                Logger::log(E_USER_NOTICE, 'Not searching user as ' . self::LDAP_AUTH_SEARCHFILTER . ' was not provided');
            
            @ldap_close($ldapConn);
            return $this->auto_create_user($login);
        }

        //Searching for user
        $filterObj = str_replace('???', $this->ldap_escape($login), Config::get(self::LDAP_AUTH_SEARCHFILTER));
        $attributes = array(Config::get(self::LDAP_AUTH_LOGIN_ATTRIB),
                            Config::get(self::LDAP_AUTH_FULLNAME_ATTRIB),
                            Config::get(self::LDAP_AUTH_EMAIL_ATTRIB));
        $searchResults = @ldap_search($ldapConn, Config::get(self::LDAP_AUTH_BASEDN), $filterObj, $attributes);
        if ($searchResults === False) {
            Logger::log(E_USER_ERROR, 'LDAP Search Failed on base \'' . Config::get(self::LDAP_AUTH_BASEDN) . '\' for \'' . $filterObj . '\'');
            @ldap_close($ldapConn);
            return False;
        }
        $count = @ldap_count_entries($ldapConn, $searchResults);
        if ($count === False) {
            Logger::log(E_USER_ERROR, 'Error searching for ' . (string) $login);
            @ldap_close($ldapConn);
            return False;            
        } elseif ($count > 1) {
            Logger::log(E_USER_ERROR, 'Multiple DNs found for username ' . (string) $login);
            @ldap_close($ldapConn);
            return False;
        } elseif ($count === 0) {
            Logger::log(E_USER_ERROR, 'Unknown User ' . (string) $login);
            @ldap_close($ldapConn);
            return False;
        }

        //Getting user's DN from search
        $userEntry = @ldap_first_entry($ldapConn, $searchResults);
        if ($userEntry === False) {
            Logger::log(E_USER_ERROR, 'LDAP search(): Unable to retrieve result after searching base \'' . Config::get(self::LDAP_AUTH_BASEDN) . '\' for \'' . $filterObj . '\'');
            @ldap_close($ldapConn);
            return false;
        }
        $userAttributes = @ldap_get_attributes($ldapConn, $userEntry);
        $userDN = @ldap_get_dn($ldapConn, $userEntry);
        if ($userDN == False) {
            Logger::log(E_USER_ERROR, 'LDAP search(): Unable to get DN after searching base \'' . Config::get(self::LDAP_AUTH_BASEDN) . '\' for \'' . $filterObj . '\'');
            @ldap_close($ldapConn);
            return false;
        }
        
        if ($this->_debugMode)
            Logger::log(E_USER_NOTICE, 'User found in DN');
        
        /**
             Bind user
         * */
        
        if ($this->_debugMode)
            Logger::log(E_USER_NOTICE, 'Try to bind with user\'s DN: ' . $userDN);

        
        $loginAttempt = @ldap_bind($ldapConn, $userDN, $password);
        if (!$loginAttempt ) {            
            Logger::log(E_USER_ERROR, 'User: ' . (string) $login . ' authentication failed');
            @ldap_close($ldapConn);
            return False;
        }

        // Conection to LDAP server not needed fter this point
        @ldap_close($ldapConn);

        if ($this->_debugMode)
            Logger::log(E_USER_NOTICE, 'User: ' . (string) $login . ' authentication successful');
   

        /**
             Create user
         * */
        
        $ttrssUsername = $login;
        if (Config::get(self::LDAP_AUTH_LOGIN_ATTRIB) != "") {
            if ($this->_debugMode)
                Logger::log(E_USER_NOTICE, 'Looking up username attribute: ' . Config::get(self::LDAP_AUTH_LOGIN_ATTRIB));
            $ttrssUsername = $userAttributes[Config::get(self::LDAP_AUTH_LOGIN_ATTRIB)][0];

            if (!is_string($ttrssUsername)) {
                Logger::log(E_USER_ERROR, 'Could not find user name attribute ' . Config::get(self::LDAP_AUTH_LOGIN_ATTRIB) . ' in LDAP entry');
                return False;
            }
        }
        
        $user_id = $this->auto_create_user($ttrssUsername);


         /**
             Update user
         * */
        
        // update user name
        if (Config::get(self::LDAP_AUTH_FULLNAME_ATTRIB) != "") {
            if ($this->_debugMode)
            Logger::log(E_USER_NOTICE, 'Looking up full name attribute: ' . Config::get(self::LDAP_AUTH_FULLNAME_ATTRIB));
            $fullname = $userAttributes[Config::get(self::LDAP_AUTH_FULLNAME_ATTRIB)][0];

            if ($fullname){
                $sth = $this->pdo->prepare("UPDATE ttrss_users SET full_name = ? WHERE id = ?");
                $sth->execute([$fullname, $user_id]);
            }
        }

        // update user mail
        if (Config::get(self::LDAP_AUTH_EMAIL_ATTRIB) != "") {
            if ($this->_debugMode)
            Logger::log(E_USER_NOTICE, 'Looking up email attribute: ' . Config::get(self::LDAP_AUTH_EMAIL_ATTRIB));
            $email = $userAttributes[Config::get(self::LDAP_AUTH_EMAIL_ATTRIB)][0];

            if ($email){
                $sth = $this->pdo->prepare("UPDATE ttrss_users SET email = ? WHERE id = ?");
                $sth->execute([$email, $user_id]);
            }
        }


        return $user_id;
    }

    /**
     * Returns plugin API version
     * Required for plugin interface
     * @return number
     */
    function api_version() {
        return 2;
    }

}

?>
