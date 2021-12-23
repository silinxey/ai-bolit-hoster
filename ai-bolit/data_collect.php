<?php

ini_set('display_errors', 'stderr');

function get_phpinfo()
{
    if (!function_exists('phpinfo') && !is_callable('phpinfo')) {
        return 'n/a';
    }
    $what = [
        'info'      => INFO_GENERAL,
        'config'    => INFO_CONFIGURATION,
        'mod'       => INFO_MODULES,
        'env'       => INFO_ENVIRONMENT,
        'var'       => INFO_VARIABLES
    ];
    $phpinfo = [];
    foreach($what as $k => $v) {
        ob_start();
        @phpinfo($v);
        $phpinfo[$k] = ob_get_clean();
    }
    return $phpinfo;
}

function get_aibolit_version($file)
{
    if (!is_file($file)) {
        return 'n/a';
    }
    $aibolit = file_get_contents($file);
    if (preg_match('~^[/\s]+(?:(?:HOSTER-)?Version:\s+)+([^\n\r]+)~m', $aibolit, $version)) {
        return $version[1];
    }
    return 'n/a';
}

function get_aibolit_db_version($file)
{
    if (!is_file($file)) {
        return 'n/a';
    }
    $avdb = explode("\n", gzinflate(base64_decode(str_rot13(strrev(trim(file_get_contents($file)))))));
    $avdb_meta_info = json_decode(base64_decode($avdb[16]), true);
    return $avdb_meta_info ? $avdb_meta_info['version'] : 'n/a';
}

function get_procu2_db_version($file)
{
    if (!is_file($file)) {
        return 'n/a';
    }
    $db_raw = explode("\n", trim(@gzinflate(base64_decode(str_rot13(strrev(trim(file_get_contents($file))))))));
    foreach ($db_raw as $line) {
        $line = trim($line);
        if ($line == '') {
            continue;
        }

        $parsed = preg_split("/\t+/", $line);

        if ($parsed[0] === 'System-Data') {
            $meta_info = json_decode($parsed[3], true);
            return $meta_info['version'];
        }
    }
    return 'n/a';
}

function get_last_file_from_progress_file($file)
{
    if (!is_file($file)) {
        return 'n/a';
    }
    $data = [];
    if (function_exists('json_decode')) {
        $data = json_decode(file_get_contents($file), true);
    } else {
        $data = unserialize(file_get_contents($file));
    }
    return $data['current_file'];
}

function get_last_file_from_mem($id)
{
    $id = shmop_open((int)$id, 'a', 0, 0);
    if (!is_resource($id) && !is_object($id)) {
        return 'n/a';
    }
    $data = [];
    if (function_exists('json_decode')) {
        $data = json_decode(rtrim(shmop_read($id, 0, 0), "\0"), true);
    } else {
        $data = unserialize(rtrim(shmop_read($id, 0, 0), "\0"));
    }
    shmop_delete($id);
    is_resource($id) ? shmop_close($id) : $id = NULL;
    return $data['current_file'];
}

function get_last_file($progress)
{
    if (is_file($progress)) {
        return get_last_file_from_progress_file($progress);
    }

    if (is_numeric($progress)) {
        return get_last_file_from_mem($progress);
    }

    return 'n/a';
}

$cli_longopts = array(
    'aibolit_file:',
    'aibolit_avdb:',
    'procu2_avdb:',
    'shared-mem-progress:',
    'progress:'
);

$result = [
    'phpinfo' => '',
    'aibolit_version' => '',
    'aibolit_db_version' => '',
    'procu2_db_version' => '',
    'last_file' => ''
];

$options = getopt('', $cli_longopts);
$where_last_file = isset($options['shared-mem-progress']) ? $options['shared-mem-progress'] : (isset($options['progress']) ? $options['progress'] : '');
$aibolit_file = isset($options['aibolit_file']) ? $options['aibolit_file'] : 'ai-bolit-hoster.php';

$result['phpinfo'] = get_phpinfo();
$result['aibolit_version'] = get_aibolit_version($aibolit_file);
$result['aibolit_db_version'] = get_aibolit_db_version($options['aibolit_avdb']);
$result['procu2_db_version'] = get_procu2_db_version($options['procu2_avdb']);
$result['last_file'] = get_last_file($where_last_file);

echo json_encode($result);

