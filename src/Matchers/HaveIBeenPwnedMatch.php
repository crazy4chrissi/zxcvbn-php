<?php

namespace ZxcvbnPhp\Matchers;

// see https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange

class HaveIBeenPwnedMatch extends Match
{

    const NUM_HASHES = 501636842; // number of hashes in the pwned database, see 	https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/
    const URL = "https://api.pwnedpasswords.com/range/";
    
    public $occurences;

    /**
     * Match occurences of pwned password.
     *
     * @copydoc Match::match()
     */
    public static function match($password, array $userInputs = array())
    {
        $sha1=strtoupper(sha1($password));
        $sha1_begin=substr($sha1, 0, 5);
        $result=file(self::URL . $sha1_begin, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if(!is_array($result))
            return array();
        foreach($result as $line) {
            $res = explode(":", $line);
            if($sha1_begin . $res[0] == $sha1) {
                $match = new static($password, 0, strlen($password) - 1, $password, $res[1]);
                return array($match);
            }
        }
        return array();
    }

    /**
     * @param $password
     * @param $begin
     * @param $end
     * @param $token
     * @param array $params
     */
    public function __construct($password, $begin, $end, $token, $occurences = 0)
    {
        parent::__construct($password, $begin, $end, $token);
        $this->pattern = 'haveibeenpwned';
        $this->occurences = $occurences;
    }

    /**
     * @return float
     */
    public function getEntropy()
    {
        if (is_null($this->entropy)) {
            // to be improved
            $this->entropy = $this->log(self::NUM_HASHES/$this->occurences);
        }
        return $this->entropy;
    }
}