<?php
# Replace 'localhost' with your FQDN and certificate CN
# for SSL verification
$request_url = "https://icinga2-master1.hosting90.cz:5665/v1/objects/services";
$username = "monweb";
$password = "UYtstksgDT4yjvPzrvfgdWf8DrLk";
$headers = array(
        'Accept: application/json',
        'X-HTTP-Method-Override: GET'
);
$data = array(
        attrs => array('name', 'state', 'last_check_result','acknowledgement'),
        joins => array('host.display_name'),
        filter => 'service.state!=ServiceOK',
);

$ch = curl_init();
curl_setopt_array($ch, array(
        CURLOPT_URL => $request_url,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_USERPWD => $username . ":" . $password,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CAINFO => "ca.crt",
        CURLOPT_POST => count($data),
        CURLOPT_POSTFIELDS => json_encode($data)
));

$response = curl_exec($ch);
if ($response === false) {
        print "Error: " . curl_error($ch) . "(" . $response . ")\n";
}

$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);
print "Status: " . $code . "\n";

if ($code == 200) {
        $response = json_decode($response, true);
        // print($response['results'][0]['attrs']['name']);
        // print($response['results'][0]['attrs']['state']);
        // print_r($response['results'][0]['joins']['host']['name']);
        // print_r($response['results'][0]['attrs']['last_check_result']['output']);
        print_r($response['results'][0]);

}
?>

