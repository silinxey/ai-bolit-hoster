<?php


$scan_signatures    = null;
$clean_signatures   = null;
$start_time         = time();
$print              = true;
$report             = null;
$lic                = null;
$detached           = null;

if (!isset($argv)) {
    $argv = $_SERVER['argv'];
}

$config = new MDSConfig();
$cli = new MDSCliParse($argv, $config);

Factory::configure($config->get(MDSConfig::PARAM_FACTORY_CONFIG));

if (!$config->get(MDSConfig::PARAM_DO_NOT_SEND_STATS)) {
    $lic = Factory::instance()->create(ImLicense::class, ['/var/imunify360/license.json', '/usr/share/imunify360/cln-pub.key']);
    if (!$lic->isValid()) {
        $config->set(MDSConfig::PARAM_DO_NOT_SEND_STATS, true);
    }
}

MDSUnixSocket::setDefaultSocket();

if ($config->get(MDSConfig::PARAM_SEARCH_CONFIGS) !== '') {
    $filter = new MDSCMSConfigFilter();
    $finder = new Finder($filter, $config->get(MDSConfig::PARAM_SEARCH_DEPTH));
    $creds = new MDSDBCredsFromConfig($finder, $config->get(MDSConfig::PARAM_SEARCH_CONFIGS));
    $tty = true;
    if (function_exists('stream_isatty') && !@stream_isatty(STDOUT)) {
        $tty = false;
    }
    if ($tty) {
        $creds->printCreds();
    } else {
        $creds->printForXArgs();
    }
    exit(0);
}

echo 'MDS - an Intelligent Malware Database Scanner for Websites.' . PHP_EOL;

$log_levels = explode(',', $config->get(MDSConfig::PARAM_LOG_LEVEL));
$log = new Logger($config->get(MDSConfig::PARAM_LOG_FILE), $log_levels);
$log->info('MDS: start');

$state = null;
$state_filepath = $config->get(MDSConfig::PARAM_STATE_FILEPATH);
if ($state_filepath) {
    $state = new MDSState($state_filepath);
    $state->setWorking();
}

if ($config->get(MDSConfig::PARAM_DETACHED)) {
    $detached = Factory::instance()->create(MDSDetachedMode::class, [$config->get(MDSConfig::PARAM_DETACHED), $config->get(MDSConfig::PARAM_OPERATION)]);
    $config->set(MDSConfig::PARAM_DO_NOT_SEND_STATS, true);
}

$filter = new MDSAVDPathFilter($config->get(MDSConfig::PARAM_IGNORELIST));

$scanned = 0;

list($scan_signatures, $clean_db) = loadMalwareSigns($config);

set_exception_handler(function ($ex) use ($report, $print, $detached, $config, $scan_signatures, $scanned) {
    if ($ex instanceof MDSException) {
        if (isset($report) && $report->getError() === null) {
            $report->addError($ex->getErrCode(), $ex->getErrMsg());
            $report->save();
        }
        if ($print) {
            print(PHP_EOL . 'Error: ' . $ex->getErrMsg() . PHP_EOL);
        }
        if ($detached) {
            if ($scanned === 0) {
                $report = createNullReport($detached->getWorkDir() . '/' . 'report0.json', $config, $scan_signatures, $detached);
                $report->addError($ex->getErrCode(), $ex->getErrMsg());
                $report->save();
            }
            $detached->complete();
        }
        exit($ex->getErrCode());
    } else {
        echo PHP_EOL . $ex->getMessage() . PHP_EOL;
        exit(-1);
    }
});

$progress = new MDSProgress($config->get(MDSConfig::PARAM_PROGRESS));
$progress->setPrint(
    function ($text) {
        $text = str_pad($text, 160, ' ', STR_PAD_RIGHT);
        echo str_repeat(chr(8), 160) . $text;
    }
);

$tables_config = new MDSTablesConfig(__DIR__ . '/mds_tables.config.json');

if (is_string($config->get(MDSConfig::PARAM_AVD_APP))) {
    $config->set(MDSConfig::PARAM_AVD_APP, [$config->get(MDSConfig::PARAM_AVD_APP)]);
} else {
    $config->set(MDSConfig::PARAM_AVD_APP, $tables_config->getSupportedApplications());
}

if (is_string($config->get(MDSConfig::PARAM_AVD_PATH)) && substr($config->get(MDSConfig::PARAM_AVD_PATH), -1) == DIRECTORY_SEPARATOR) {
    $config->set(MDSConfig::PARAM_AVD_PATH, substr($config->get(MDSConfig::PARAM_AVD_PATH), 0, -1));
}

if ($config->get(MDSConfig::PARAM_AVD_PATHS) && file_exists($config->get(MDSConfig::PARAM_AVD_PATHS))) {
    $paths = file($config->get(MDSConfig::PARAM_AVD_PATHS), FILE_SKIP_EMPTY_LINES | FILE_IGNORE_NEW_LINES);
    foreach ($paths as &$path) {
        $path = base64_decode($path);
        if (substr($path, -1) == DIRECTORY_SEPARATOR) {
            $path = substr($path, 0, -1);
        }
    }
    $config->set(MDSConfig::PARAM_AVD_PATHS, $paths);
}

$creds = getCreds($config, $argc, $argv, $progress);

$prescan ='';
if (file_exists(__DIR__ . '/mds_prescan.config.bin')) {
    $prescan = trim(file_get_contents(__DIR__ . '/mds_prescan.config.bin'));
} else {
    throw new MDSException(MDSErrors::MDS_PRESCAN_CONFIG_ERROR, __DIR__ . '/mds_prescan.config.bin');
}

foreach($creds as $i => $cred) {
    try {
        if (($cred === false) || (isset($cred['db_path']) && $filter && MDSConfig::PARAM_AVD_PATH && !$filter->needToScan($cred['db_path']))) {
            continue;
        }
        $report = null;
        if (isset($cred['error'])) {
            throw $cred['error'];
        }
        if (!ini_get('mysqli.default_socket') && $cred['db_host'] === 'localhost') {
            $cred['db_host'] = gethostbyname($cred['db_host']);
        }
        $config->set(MDSConfig::PARAM_HOST, $cred['db_host']);
        $config->set(MDSConfig::PARAM_PORT, $cred['db_port']);
        $config->set(MDSConfig::PARAM_LOGIN, $cred['db_user']);
        $config->set(MDSConfig::PARAM_PASSWORD, $cred['db_pass']);
        $config->set(MDSConfig::PARAM_DATABASE, $cred['db_name']);
        $config->set(MDSConfig::PARAM_PREFIX, $cred['db_prefix']);

        if ($config->get(MDSConfig::PARAM_OVERRIDE_PORT)) {
            $config->set(MDSConfig::PARAM_PORT, $config->get(MDSConfig::PARAM_OVERRIDE_PORT));
        }
        if ($config->get(MDSConfig::PARAM_OVERRIDE_HOST)) {
            $config->set(MDSConfig::PARAM_HOST, $config->get(MDSConfig::PARAM_OVERRIDE_HOST));
        }

        scanDB($config, $scan_signatures, $progress, $log, $tables_config, $prescan, $clean_db, $state, $lic, $i,
            $detached, $cred);

        $scanned++;
    } catch (MDSException $ex) {
        if (isset($detached)) {
            if ($report === null) {
                $report = createNullReport($detached->getWorkDir() . '/' . 'report' . $i . '.json', $config, $scan_signatures, $detached);
            }
            $report->addError($ex->getErrCode(), $ex->getErrMsg());
            $report->save();
        } else if (!isset($detached) && ($progress->getDbCount() > 1)) {
            echo PHP_EOL . $ex->getErrMsg() . PHP_EOL;
        } else {
            throw $ex;
        }
    }
}

if ($scanned === 0) {
    throw new MDSException(MDSErrors::MDS_NO_SCANNED);
}

if ($detached) {
    $detached->complete();
}

if ($state && !$state->isCanceled()) {
    $state->setDone();
}

exit(0);
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
function createNullReport($filename, $config, $scan_signatures = null, $detached = null)
{
    $report = new MDSJSONReport(
        time(),
        $filename,
        '0.001-dev',
        isset($scan_signatures) ? $scan_signatures->getDBMetaInfoVersion() : '',
        '',
        '',
        '',
        ''
    );
    if ($report->getError() !== null) {
        throw $report->getError();
    }
    if (isset($config)) {
        setOpFromConfig($config, $report, $detached);
    }
    $report->setPath(null);
    $report->setApp(null);
    return $report;
}

function getCreds($config, $argc, $argv, $progress)
{
    $creds = [];
    if ($config->get(MDSConfig::PARAM_AVD_PATH) || $config->get(MDSConfig::PARAM_AVD_PATHS)) {
        $avd_creds = Factory::instance()->create(MDSDBCredsFromAVD::class);
        $recursive = $config->get(MDSConfig::PARAM_SCAN);
        $paths = $config->get(MDSConfig::PARAM_AVD_PATHS) ? $config->get(MDSConfig::PARAM_AVD_PATHS) : [$config->get(MDSConfig::PARAM_AVD_PATH), $config->get(MDSConfig::PARAM_AVD_PATH) . '/*'];
        $avd_creds->countApps($paths, $config->get(MDSConfig::PARAM_AVD_APP), $recursive);
        $creds = $avd_creds->getCredsFromApps($paths, $config->get(MDSConfig::PARAM_AVD_APP), $recursive);
        $progress->setDbCount($avd_creds->getAppsCount());
    } elseif ($config->get(MDSConfig::PARAM_CREDS_FROM_XARGS)) {
        $creds_xargs = explode(';;', $argv[$argc - 1]);
        $creds[] = [
            'db_host'   => $creds_xargs[0],
            'db_port'   => $creds_xargs[1],
            'db_user'   => $creds_xargs[2],
            'db_pass'   => $creds_xargs[3],
            'db_name'   => $creds_xargs[4],
            'db_prefix' => $creds_xargs[5],
        ];
        $progress->setDbCount(1);
    } else {
        $password = $config->get(MDSConfig::PARAM_PASSWORD);
        if ($config->get(MDSConfig::PARAM_PASSWORD_FROM_STDIN)) {
            $f = @fopen('php://stdin', 'r');
            echo "Enter password for db:" . PHP_EOL;
            $password = str_replace("\n","", fgets($f));
            fclose($f);
        }
        $creds[] = [
            'db_host'   => $config->get(MDSConfig::PARAM_HOST),
            'db_port'   => $config->get(MDSConfig::PARAM_PORT),
            'db_user'   => $config->get(MDSConfig::PARAM_LOGIN),
            'db_pass'   => $password,
            'db_name'   => $config->get(MDSConfig::PARAM_DATABASE),
            'db_prefix' => $config->get(MDSConfig::PARAM_PREFIX),
        ];
        $progress->setDbCount(1);
    }
    return $creds;
}

function scanDB($config, $scan_signatures, $progress, $log, $tables_config, $prescan, $clean_db, $state, $lic, $i, $detached, $cred)
{
    try {
        $backup = null;
        if (empty($config->get(MDSConfig::PARAM_DATABASE))) {
            throw new MDSException(MDSErrors::MDS_NO_DATABASE);
        }

        if ($progress->getDbCount() > 1 && !$config->get(MDSConfig::PARAM_SCAN)) {
            throw new MDSException(MDSErrors::MDS_MULTIPLE_DBS);
        }

        $progress->setCurrentDb($i, $config->get(MDSConfig::PARAM_DATABASE));

        $log->info('MDS DB scan: started ' . $config->get(MDSConfig::PARAM_DATABASE));

        $report_filename = 'dbscan-' . $config->get(MDSConfig::PARAM_DATABASE) . '-' . $config->get(MDSConfig::PARAM_LOGIN) . '-' . time() . '.json';


        if ($config->get(MDSConfig::PARAM_DETACHED)) {
            $config->set(MDSConfig::PARAM_REPORT_FILE, $detached->getWorkDir() . '/' . 'report' . $i . '.json');
        }

        if (!$config->get(MDSConfig::PARAM_REPORT_FILE)) {
            $report_file = __DIR__ . '/' . $report_filename;
        } else {
            if (is_dir($config->get(MDSConfig::PARAM_REPORT_FILE))) {
                $report_file = $config->get(MDSConfig::PARAM_REPORT_FILE) . '/' . $report_filename;
            } else {
                $report_file = $config->get(MDSConfig::PARAM_REPORT_FILE);
            }
        }

        $report = new MDSJSONReport(
            time(),
            $report_file,
            '0.001-dev',
            isset($scan_signatures) ? $scan_signatures->getDBMetaInfoVersion() : '',
            $config->get(MDSConfig::PARAM_HOST),
            $config->get(MDSConfig::PARAM_DATABASE),
            $config->get(MDSConfig::PARAM_LOGIN),
            $config->get(MDSConfig::PARAM_PORT)
        );

        if ($report->getError() !== null) {
            throw $report->getError();
        }

        $report->setMalwareDbVer($scan_signatures->getDBMetaInfoVersion());

        setOpFromConfig($config, $report, $detached);

        $report->setScanId($config->get(MDSConfig::PARAM_DETACHED));

        if (isset($cred['db_app'])) {
            $report->setApp($cred['db_app']);
        }

        if (isset($cred['app_owner_uid'])) {
            $report->setAppOwnerUId($cred['app_owner_uid']);
        }

        if (isset($cred['db_path'])) {
            $report->setPath($cred['db_path']);
        }

        if ($config->get(MDSConfig::PARAM_CLEAN)) {
            $backup = new MDSBackup($config->get(MDSConfig::PARAM_BACKUP_FILEPATH));
        }

        mysqli_report(MYSQLI_REPORT_STRICT);
        $db_connection = mysqli_init();
        $db_connection->options(MYSQLI_OPT_CONNECT_TIMEOUT, $config->get(MDSConfig::PARAM_DB_TIMEOUT));
        $db_connection->options(MYSQLI_OPT_READ_TIMEOUT, $config->get(MDSConfig::PARAM_DB_TIMEOUT));
        if (!$db_connection->real_connect($config->get(MDSConfig::PARAM_HOST), $config->get(MDSConfig::PARAM_LOGIN),
            $config->get(MDSConfig::PARAM_PASSWORD),
            $config->get(MDSConfig::PARAM_DATABASE), $config->get(MDSConfig::PARAM_PORT))) {
            $log->error('Can\'t connect to database: ' . $db_connection->connect_error);
            throw new MDSException(MDSErrors::MDS_CONNECT_ERROR, $db_connection->connect_error);
        }

        $base64_sup = false;
        $db_connection->set_charset('utf8');
        $res = @$db_connection->query('SELECT count(TO_BASE64("test")) > 0;');
        if ($res instanceof \mysqli_result) {
            $base64_sup = true;
        }

        if (!$base64_sup) {
            $tables_config->disableBase64();
            $report->setBase64(false);
        }

        $mds_find = new MDSFindTables($db_connection, $tables_config);

        if (!$config->get(MDSConfig::PARAM_DONT_SEND_UNK_URLS)) {
            $report->setUnknownUrlsSend(new MDSSendUrls(Factory::instance()->create(MDSCollectUrlsRequest::class)));
        }

        if ($config->get(MDSConfig::PARAM_CLEAN) || $config->get(MDSConfig::PARAM_SCAN)) {
            MDSScanner::scan($prescan, $config->get(MDSConfig::PARAM_DATABASE), $config->get(MDSConfig::PARAM_PREFIX),
                $mds_find, $db_connection, $scan_signatures,
                $config->get(MDSConfig::PARAM_MAX_CLEAN_BATCH), $clean_db, $progress, $state, $report, $backup,
                $config->get(MDSConfig::PARAM_SCAN), $config->get(MDSConfig::PARAM_CLEAN), $log);
        }

        if ($config->get(MDSConfig::PARAM_RESTORE)) {
            $report->setOp($config->get(MDSConfig::PARAM_OPERATION));
            $restore = new MDSRestore($config->get(MDSConfig::PARAM_RESTORE), $db_connection, $progress, $report,
                $state,
                $log);
            $restore->restore($config->get(MDSConfig::PARAM_MAX_RESTORE_BATCH));
            $restore->finish();
        }

        $ch = null;
        if (!$config->get(MDSConfig::PARAM_DO_NOT_SEND_STATS)) {
            $request = new MDSCHRequest();
            $ch = Factory::instance()->create(MDSSendToCH::class, [$request, $lic]);
        }

        if ($report) {
            $report->setCH($ch);
            $report->save();
        }

        $db_connection->close();
        $log->info('MDS DB scan: finished ' . $config->get(MDSConfig::PARAM_DATABASE));

    } catch (MDSException $ex) {
        onError($detached, $progress, $report, $ex);
    } catch (mysqli_sql_exception $e) {
        $ex = new MDSException(MDSErrors::MDS_CONNECT_ERROR, $config->get(MDSConfig::PARAM_LOGIN) . '@' . $config->get(MDSConfig::PARAM_HOST));
        onError($detached, $progress, $report, $ex);
    }
}

function onError($detached, $progress, $report, $ex)
{
    if ((isset($detached) || ($progress->getDbCount() > 1)) && (isset($report) && $report->getError() === null)) {
        $report->setPath(null);
        $report->setApp(null);
        $report->addError($ex->getErrCode(), $ex->getErrMsg());
        $report->save();
    } else {
        throw $ex;
    }
}

function setOpFromConfig($config, $report, $detached = null)
{
    $report->setOp($config->get(MDSConfig::PARAM_OPERATION));

    if (!isset($detached)) {
        return;
    }

    $detached->setOp($config->get(MDSConfig::PARAM_OPERATION));
}

function loadMalwareSigns($config)
{
    $scan_signatures = null;
    $clean_signatures = null;

    if ($config->get(MDSConfig::PARAM_SCAN) || $config->get(MDSConfig::PARAM_CLEAN) || $config->get(MDSConfig::PARAM_RESTORE)) {
        $avdb = trim($config->get(MDSConfig::PARAM_AV_DB));
        $scan_signatures = new LoadSignaturesForScan($avdb, 2, 0);
        if ($scan_signatures->getResult() == LoadSignaturesForScan::SIGN_EXTERNAL) {
            echo 'Loaded external scan signatures from ' . $avdb . PHP_EOL;
        }
        $sign_count = $scan_signatures->getDBCount();
        echo 'Malware scan signatures: ' . $sign_count . PHP_EOL;

        $blackUrls = file_exists('/var/imunify360/files/sigs/v1/aibolit/blacklistedUrls.db') ?
            '/var/imunify360/files/sigs/v1/aibolit/blacklistedUrls.db' : __DIR__ . '/blacklistedUrls.db';

        $whiteUrls = file_exists('/var/imunify360/files/sigs/v1/aibolit/whitelistUrls.db') ?
            '/var/imunify360/files/sigs/v1/aibolit/whitelistUrls.db' : __DIR__ . '/whitelistUrls.db';


        $scan_signatures->blackUrls = new MDSUrls($blackUrls);
        $scan_signatures->whiteUrls = new MDSUrls($whiteUrls);

        if ($config->get(MDSConfig::PARAM_CLEAN)) {
            $procudb = trim($config->get(MDSConfig::PARAM_PROCU_DB));
            $clean_signatures = new LoadSignaturesForClean('', $procudb);
            if ($clean_signatures->getDBLocation() == 'external') {
                echo 'Loaded external clean signatures from ' . $procudb . PHP_EOL;
            }
            $clean_db = $clean_signatures->getDB();
            $clean_signatures->setScanDB($scan_signatures);
            echo 'Malware clean signatures: ' . count($clean_db) . PHP_EOL;
        }
        echo PHP_EOL;
    }
    return [$scan_signatures, $clean_signatures];
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////


/**
 * Class Factory.
 */
class Factory
{
    /**
     * @var Factory
     */
    private static $instance;
    /**
     * @var array
     */
    private static $config;

    /**
     * Factory constructor.
     *
     * @throws Exception
     */
    private function __construct()
    {

    }

    /**
     * Instantiate and return a factory.
     *
     * @return Factory
     * @throws Exception
     */
    public static function instance()
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    /**
     * Configure a factory.
     *
     * This method can be called only once.
     *
     * @param array $config
     * @throws Exception
     */
    public static function configure($config = [])
    {
        if (self::isConfigured()) {
            throw new Exception('The Factory::configure() method can be called only once.');
        }

        self::$config = $config;
    }

    /**
     * Return whether a factory is configured or not.
     *
     * @return bool
     */
    public static function isConfigured()
    {
        return self::$config !== null;
    }

    /**
     * Creates and returns an instance of a particular class.
     *
     * @param string $class
     *
     * @param array $constructorArgs
     * @return mixed
     * @throws Exception
     */
    public function create($class, $constructorArgs = [])
    {
        if (!isset(self::$config[$class])) {
            throw new Exception("The factory is not contains configuration for '{$class}'.");
        }

        if (is_callable(self::$config[$class])) {
            return call_user_func(self::$config[$class], $constructorArgs);
        } else {
            return new self::$config[$class](...$constructorArgs);
        }
    }
}
class Config
{
    /**
     * @var array Configuration data 
     */
    private $config     = [];

    /**
     * Returns valued of a particular option.
     *
     * @param string $key
     * @return mixed
     * @throws Exception
     */
    public function get($key)
    {
        if (!array_key_exists($key, $this->config)) {
            throw new Exception('An invalid option requested. Key: ' . $key);
        }
        return $this->config[$key];
    }

    /**
     * Set value to config by key
     *
     * @param string $key
     * @param mixed $value
     * @return mixed
     * @throws Exception
     */
    public function set($key, $value)
    {
        $this->config[$key] = $value;
    }

    /**
     * Set default config
     *
     * @param array $defaults
     */
    protected function setDefaultConfig($defaults)
    {
        $this->config = $defaults;
    }
}
class MDSConfig extends Config
{
    const PARAM_HELP                = 'help';
    const PARAM_VERSION             = 'version';
    const PARAM_HOST                = 'host';
    const PARAM_PORT                = 'port';
    const PARAM_LOGIN               = 'login';
    const PARAM_PASSWORD            = 'password';
    const PARAM_PASSWORD_FROM_STDIN = 'password-from-stdin';
    const PARAM_DATABASE            = 'database';
    const PARAM_PREFIX              = 'prefix';
    const PARAM_SCAN                = 'scan';
    const PARAM_CLEAN               = 'clean';
    const PARAM_REPORT_FILE         = 'report-file';
    const PARAM_SIGDB               = 'signature-db';
    const PARAM_PROGRESS            = 'progress';
    const PARAM_FACTORY_CONFIG      = 'factory-config';
    const PARAM_AV_DB               = 'avdb';
    const PARAM_PROCU_DB            = 'procudb';
    const PARAM_SHARED_MEM          = 'shared-mem-progress';
    const PARAM_SHARED_MEM_CREATE   = 'create-shared-mem';
    const PARAM_STATE_FILEPATH      = 'state-file';
    const PARAM_MAX_CLEAN_BATCH     = 'max-clean';
    const PARAM_MAX_RESTORE_BATCH   = 'max-restore';
    const PARAM_RESTORE             = 'restore';
    const PARAM_LOG_FILE            = 'log-file';
    const PARAM_BACKUP_FILEPATH     = 'backup-file';
    const PARAM_LOG_LEVEL           = 'log-level';
    const PARAM_DONT_SEND_UNK_URLS  = 'do-not-send-urls';
    const PARAM_SEARCH_CONFIGS      = 'search-configs';
    const PARAM_SEARCH_DEPTH        = 'search-depth';
    const PARAM_CREDS_FROM_XARGS    = 'creds-from-xargs';
    const PARAM_OVERRIDE_PORT       = 'override_port';
    const PARAM_OVERRIDE_HOST       = 'override_host';
    const PARAM_DO_NOT_SEND_STATS   = 'do-not-send-stats';
    const PARAM_DB_TIMEOUT          = 'db-timeout';
    const PARAM_DETACHED            = 'detached';
    const PARAM_AVD_APP             = 'app-name';
    const PARAM_AVD_PATH            = 'path';
    const PARAM_AVD_PATHS           = 'paths';
    const PARAM_RESCAN              = 'rescan';
    const PARAM_IGNORELIST          = 'ignore-list';
    const PARAM_OPERATION           = 'op';

    /**
     * @var array Default config
     */
    protected $defaultConfig = [
        self::PARAM_HELP                => false,
        self::PARAM_VERSION             => false,
        self::PARAM_SCAN                => false,
        self::PARAM_CLEAN               => false,
        self::PARAM_HOST                => '127.0.0.1',
        self::PARAM_PORT                => 3306,
        self::PARAM_LOGIN               => null,
        self::PARAM_PASSWORD            => null,
        self::PARAM_PASSWORD_FROM_STDIN => false,
        self::PARAM_DATABASE            => null,
        self::PARAM_PREFIX              => null,
        self::PARAM_REPORT_FILE         => null,
        self::PARAM_SIGDB               => null,
        self::PARAM_PROGRESS            => null,
        self::PARAM_FACTORY_CONFIG      => [
            MDSDetachedMode::class          => MDSDetachedMode::class,
            MDSDBCredsFromAVD::class        => MDSDBCredsFromAVD::class,
            ImLicense::class                => ImLicense::class,
            MDSSendToCH::class              => MDSSendToCH::class,
            MDSCollectUrlsRequest::class    => MDSCollectUrlsRequest::class,
        ],
        self::PARAM_AV_DB               => null,
        self::PARAM_PROCU_DB            => null,
        self::PARAM_SHARED_MEM          => false,
        self::PARAM_SHARED_MEM_CREATE   => false,
        self::PARAM_STATE_FILEPATH      => null,
        self::PARAM_MAX_CLEAN_BATCH     => 100,
        self::PARAM_MAX_RESTORE_BATCH   => 100,
        self::PARAM_RESTORE             => null,
        self::PARAM_LOG_FILE            => null,
        self::PARAM_LOG_LEVEL           => 'INFO',
        self::PARAM_DONT_SEND_UNK_URLS  => false,
        self::PARAM_SEARCH_CONFIGS      => '',
        self::PARAM_SEARCH_DEPTH        => 3,
        self::PARAM_CREDS_FROM_XARGS    => false,
        self::PARAM_OVERRIDE_PORT       => false,
        self::PARAM_OVERRIDE_HOST       => false,
        self::PARAM_BACKUP_FILEPATH     => '',
        self::PARAM_DO_NOT_SEND_STATS   => false,
        self::PARAM_DB_TIMEOUT          => 15,
        self::PARAM_DETACHED            => false,
        self::PARAM_AVD_APP             => false,
        self::PARAM_AVD_PATH            => false,
        self::PARAM_AVD_PATHS           => false,
        self::PARAM_RESCAN              => false,
        self::PARAM_IGNORELIST          => false,
        self::PARAM_OPERATION           => false,
    ];

    /**
     * Construct
     */
    public function __construct() 
    {
        $this->setDefaultConfig($this->defaultConfig);
    }
}
/*
 * Abstract class for parse cli command
 */
abstract class CliParse
{
    /**
     * @var Config Config for fill
     */
    protected $config = null;
    
    /**
     * @var array List of options. Example of one element: ['short' => 'v', 'long' => 'version,ver', 'needValue' => false]
     */
    protected $opts     = [];
    
    /**
     * @var array Current of options from $argv
     */
    private $options    = [];
    
    /**
     * @var array Arguments left after getopt() processing
     */
    private $freeAgrs   = [];
    
    /**
     * Construct
     *
     * @param array $argv
     * @param Config $config
     * @throws Exception
     */
    public function __construct($argv, Config $config)
    {
        $this->config   = $config;
        $cliLongOpts    = [];
        $cliShortOpts   = [];
        foreach ($this->opts as $params) {
            $postfix = $params['needValue'] ? ':' : '';
            if ($params['long']) {
                $cliLongOpts = array_merge($cliLongOpts, $this->getMultiOpts($params['long'], $params['needValue']));
            }
            if ($params['short']) {
                $cliShortOpts = array_merge($cliShortOpts, $this->getMultiOpts($params['short'], $params['needValue']));
            }
        }
        $this->parseOptions($argv, $cliShortOpts, $cliLongOpts);
        $this->parse();
    }
    
    /**
     * Parse comand line params
     */
    abstract protected function parse();

    /**
     * Checking if the parameter was used in the cli line
     *
     * @param string $paramKey
     * @return bool
     * @throws Exception
     */
    protected function issetParam($paramKey)
    {
        if (!isset($this->opts[$paramKey])) {
            throw new Exception('An invalid option requested.');
        }
        if ($this->getExistingOpt($this->opts[$paramKey]['long'])) {
            return true;
        }
        elseif ($this->getExistingOpt($this->opts[$paramKey]['short'])) {
            return true;
        }
        return false;
    }

    /**
     * Checking if the parameter was used in the cli line
     *
     * @param string $paramKey
     * @return bool
     * @throws Exception
     */
    protected function getParamValue($paramKey, $default = null)
    {
        if (!isset($this->opts[$paramKey])) {
            throw new Exception('An invalid option requested.');
        }
        $existingLongOpt = $this->getExistingOpt($this->opts[$paramKey]['long']);
        if ($existingLongOpt) {
            return $this->options[$existingLongOpt];
        }
        $existingShortOpt = $this->getExistingOpt($this->opts[$paramKey]['short']);
        if ($existingShortOpt) {
            return $this->options[$existingShortOpt];
        }
        return $default;
    }

    /**
     * Return free arguments after using getopt()
     *
     * @return array
     * @throws Exception
     */
    protected function getFreeAgrs()
    {
        return $this->freeAgrs;
    }
    
    /**
     * Parse by getopt() and fill vars: $this->options $this->freeAgrs
     * 
     * @return void
     */
    private function parseOptions($argv, $cliShortOpts, $cliLongOpts)
    {
        if (count($argv) <= 1) {
            return;
        }
        $this->options  = getopt(implode('', $cliShortOpts), $cliLongOpts);
        //$this->freeAgrs = array_slice($argv, $optind); // getopt(,,$optind) only for PHP7.1 and upper
        
        for($i = 1; $i < count($argv); $i++) {
            if (strpos($argv[$i], '-') !== 0) {
                $this->freeAgrs = array_slice($argv, $i);
                break;
            }
        }
    }    

    /**
     * Clean cli parameter
     *
     * @param string $optName Paramenter may be with ":" postfix
     * @return array
     */
    private function getCleanOptName($optName)
    {
        return str_replace(':', '', $optName);
    }
    
    /**
     * Return options with or without ":" postfix
     *
     * @param array $optString String with one or more options separated by ","
     * @param bool $addPostfix True if need add postfix
     * @return array Array list of options
     */
    private function getMultiOpts($optString, $addPostfix = false)
    {
        $opts = explode(',', $optString);
        if ($addPostfix) {
            $opts = array_map(function($value) { 
                return $value . ':';
            }, $opts);
        }
        return $opts;
    }
    
    /**
     * Return existing options from string. 
     *
     * @param string $optsString String with one or more options separated by ","
     * @return string|bool Name of finded options in getopt()
     */
    private function getExistingOpt($optsString)
    {
        $opts = $this->getMultiOpts($optsString);
        foreach ($opts as $opt) {
            if (isset($this->options[$opt])) { 
                return $opt;
            }
        }
        return false;
    }
}
/*
 * Abstract class for MDS which can parse cli command
 */
class MDSCliParse extends CliParse
{
    /**
     * @var array Project options for cli
     */
    protected $opts = [
        MDSConfig::PARAM_HELP                   => ['short' => 'h', 'long' => 'help',                   'needValue' => false],
        MDSConfig::PARAM_VERSION                => ['short' => 'v', 'long' => 'version,ver',            'needValue' => false],
        MDSConfig::PARAM_HOST                   => ['short' => '',  'long' => 'host',                   'needValue' => true],
        MDSConfig::PARAM_PORT                   => ['short' => '',  'long' => 'port',                   'needValue' => true],
        MDSConfig::PARAM_LOGIN                  => ['short' => '',  'long' => 'login',                  'needValue' => true],
        MDSConfig::PARAM_PASSWORD               => ['short' => '',  'long' => 'password',               'needValue' => true],
        MDSConfig::PARAM_PASSWORD_FROM_STDIN    => ['short' => '',  'long' => 'password-from-stdin',    'needValue' => false],
        MDSConfig::PARAM_DATABASE               => ['short' => '',  'long' => 'database',               'needValue' => true],
        MDSConfig::PARAM_PREFIX                 => ['short' => '',  'long' => 'prefix',                 'needValue' => true],
        MDSConfig::PARAM_SCAN                   => ['short' => '',  'long' => 'scan',                   'needValue' => false],
        MDSConfig::PARAM_CLEAN                  => ['short' => '',  'long' => 'clean',                  'needValue' => false],
        MDSConfig::PARAM_REPORT_FILE            => ['short' => '',  'long' => 'report-file',            'needValue' => true],
        MDSConfig::PARAM_SIGDB                  => ['short' => '',  'long' => 'signature-db',           'needValue' => true],
        MDSConfig::PARAM_PROGRESS               => ['short' => '',  'long' => 'progress',               'needValue' => true],
        MDSConfig::PARAM_AV_DB                  => ['short' => '',  'long' => 'avdb',                   'needValue' => true],
        MDSConfig::PARAM_PROCU_DB               => ['short' => '',  'long' => 'procudb',                'needValue' => true],
        MDSConfig::PARAM_SHARED_MEM             => ['short' => '',  'long' => 'shared-mem-progress',    'needValue' => true],
        MDSConfig::PARAM_SHARED_MEM_CREATE      => ['short' => '',  'long' => 'create-shared-mem',      'needValue' => false],
        MDSConfig::PARAM_STATE_FILEPATH         => ['short' => '',  'long' => 'state-file',             'needValue' => true],
        MDSConfig::PARAM_RESTORE                => ['short' => '',  'long' => 'restore',                'needValue' => true],
        MDSConfig::PARAM_LOG_FILE               => ['short' => '',  'long' => 'log-file',               'needValue' => true],
        MDSConfig::PARAM_LOG_LEVEL              => ['short' => '',  'long' => 'log-level',              'needValue' => true],
        MDSConfig::PARAM_DONT_SEND_UNK_URLS     => ['short' => '',  'long' => 'do-not-send-urls',       'needValue' => false],
        MDSConfig::PARAM_SEARCH_CONFIGS         => ['short' => '',  'long' => 'search-configs',         'needValue' => true],
        MDSConfig::PARAM_SEARCH_DEPTH           => ['short' => '',  'long' => 'search-depth',           'needValue' => true],
        MDSConfig::PARAM_CREDS_FROM_XARGS       => ['short' => '',  'long' => 'creds-from-xargs',       'needValue' => false],
        MDSConfig::PARAM_OVERRIDE_PORT          => ['short' => '',  'long' => 'override_port',          'needValue' => true],
        MDSConfig::PARAM_OVERRIDE_HOST          => ['short' => '',  'long' => 'override_host',          'needValue' => true],
        MDSConfig::PARAM_BACKUP_FILEPATH        => ['short' => '',  'long' => 'backup-file',            'needValue' => true],
        MDSConfig::PARAM_DO_NOT_SEND_STATS      => ['short' => '',  'long' => 'do-not-send-stats',      'needValue' => false],
        MDSConfig::PARAM_DB_TIMEOUT             => ['short' => '',  'long' => 'db-timeout',             'needValue' => true],
        MDSConfig::PARAM_DETACHED               => ['short' => '',  'long' => 'detached',               'needValue' => true],
        MDSConfig::PARAM_FACTORY_CONFIG         => ['short' => '',  'long' => 'factory-config',         'needValue' => true],
        MDSConfig::PARAM_AVD_APP                => ['short' => '',  'long' => 'app-name',               'needValue' => true],
        MDSConfig::PARAM_AVD_PATH               => ['short' => '',  'long' => 'path',                   'needValue' => true],
        MDSConfig::PARAM_AVD_PATHS              => ['short' => '',  'long' => 'paths',                  'needValue' => true],
        MDSConfig::PARAM_IGNORELIST             => ['short' => '',  'long' => 'ignore-list',            'needValue' => true],
    ];

    /**
     * Parse comand line params
     * 
     * @return void
     * @throws Exception
     */
    protected function parse()
    {
        foreach ($this->opts as $configName => $params) {
            $default    = $params['needValue'] ? $this->config->get($configName) : null;
            $result     = $this->getParamValue($configName, $default);
            if (!$params['needValue'] && $result === false) { // $result === false because opt without value
                $result = true;
            }
            if ($configName == MDSConfig::PARAM_FACTORY_CONFIG) {
                $file = $result;
                if (is_string($file) && !empty($file) && @file_exists($file) && @is_readable($file) && @filesize($file) > 5) {
                    $optionalFactoryConfig = require($file);
                    $result = array_merge($this->config->get(MDSConfig::PARAM_FACTORY_CONFIG), $optionalFactoryConfig);
                }
            }
            $this->config->set($configName, $result);
        }
        
        $factoryConfig = $this->config->get(MDSConfig::PARAM_FACTORY_CONFIG);

        if ($this->config->get(MDSConfig::PARAM_SCAN)) {
            $this->config->set(MDSConfig::PARAM_OPERATION, MDSConfig::PARAM_SCAN);
        } else if ($this->config->get(MDSConfig::PARAM_CLEAN)) {
            $this->config->set(MDSConfig::PARAM_OPERATION, MDSConfig::PARAM_CLEAN);
        } else if ($this->config->get(MDSConfig::PARAM_RESTORE)) {
            $this->config->set(MDSConfig::PARAM_OPERATION, MDSConfig::PARAM_RESTORE);
        }
        
        if ($this->config->get(MDSConfig::PARAM_HELP)) {
            $this->showHelp();
        }
        elseif ($this->config->get(MDSConfig::PARAM_VERSION)) {
            $this->showVersion();
        }
        elseif (!$this->config->get(MDSConfig::PARAM_OPERATION) && !$this->config->get(MDSConfig::PARAM_SEARCH_CONFIGS)) {
            $this->showHelp();
        }
        
        // here maybe re-define some of $factoryConfig elements 
        
        $this->config->set(MDSConfig::PARAM_FACTORY_CONFIG, $factoryConfig);
    }
    
    /**
     * Cli show help
     * 
     * @return void
     */
    private function showHelp()
    {
        echo <<<HELP
MDS - an Intelligent Malware Database Scanner for Websites.

Usage: php {$_SERVER['PHP_SELF']} [OPTIONS]

      --host=<host>                     Database host ('localhost' used for file socket connection, for TCP-IP use '127.0.0.1')
      --port=<port>                     Database port
      --login=<username>                Database username
      --password=<password>             Database password
      --password-from-stdin             Get database password from stdin
      --database=<db_name>              Database name
      --prefix=<prefix>                 Prefix for table
      --scan                            Do scan
      --clean                           Do clean
      --report-file=<filepath>          Filepath where to put the report
      --signature-db=<filepath>         Filepath with signatures
      --progress=<filepath>             Filepath with progress
      --shared-mem-progress=<shmem_id>  ID of shared memory segment
      --create-shared-mem               MDS create own shared memory segment
      --state=<filepath>                Filepath with state for control task
      --backup-filepath=<filepath>      Backup file
      --avdb=<filepath>                 Filepath with ai-bolit signatures db
      --procudb=<filepath>              Filepath with procu signatures db
      --state-file=<filepath>           Filepath with info about state(content: new|working|done|canceled). You can change it on canceled
      --restore=<filepath>              Filepath to restore csv file
      --log-file=<filepath>             Filepath to log file
      --log-level=<LEVEL>               Log level (types: ERROR|DEBUG|INFO|ALL). You can use multiple by using comma (example: DEBUG,INFO)
      --do-not-send-urls                Do not send unknown urls to server for deeper analysis
      --search-configs                  Search supported CMS configs and print db credentials
      --search-depth=<depth>            Search depth for CMS configs (default: 3)
      --creds-from-xargs                Get db credentials from last free arg (template: host;;port;;user;;pass;;name)
      --do-not-send-stats               Do not send report to Imunify correlation server
      --db-timeout=<timeout>            Timeout for connect/read db in seconds
      --detached=<scan_id>              Run MDS in detached mode
      --path=<path>                     Scan/clean CMS dbs from <path> with help AppVersionDetector
      --paths=<file>                    Scan/clean CMS dbs base64 encoded paths from <file> with help AppVersionDetector
      --app-name=<app-name>             Filter AppVersionDetector dbs for scan with <app-name>. Currently supported only 'wp-core'.

  -h, --help                            Display this help and exit
  -v, --version                         Show version


HELP;
        exit(0);
    }

    /**
     * Cli show version
     * 
     * @return void
     */
    private function showVersion()
    {
        echo "Unknown\n";
        exit(0);
    }
}
/**
 * Class MDSTablesConfig for work with config file in MDS
 */
class MDSTablesConfig
{
    private $raw_config = [];

    /**
     * MDSTablesConfig constructor.
     * @param $file
     * @throws Exception
     */
    public function __construct($file)
    {
        if (empty($file) || !file_exists($file)) {
            throw new MDSException(MDSErrors::MDS_CONFIG_ERROR, $file);
        }

        $this->raw_config = json_decode(file_get_contents($file), true);
    }

    /**
     * Get all applications defined in config
     * @return array
     */
    public function getSupportedApplications()
    {
        return array_keys($this->raw_config['applications']);
    }

    /**
     * Get all tables defined in config for application
     * @param $application
     * @return array
     */
    public function getSupportedTables($application)
    {
        return isset($this->raw_config['applications'][$application]) ? array_keys($this->raw_config['applications'][$application]) : [];
    }

    /**
     * Get all fields defined in config for table in application
     * @param $application
     * @param $table
     * @return array|mixed
     */
    public function getTableFields($application, $table)
    {
        return $this->raw_config['applications'][$application][$table]['fields'] ?? [];
    }

    /**
     * Get key field defined in config for table in application
     * @param $application
     * @param $table
     * @return string
     */
    public function getTableKey($application, $table)
    {
        return $this->raw_config['applications'][$application][$table]['key'] ?? '';
    }

    /**
     * Get array of defined in config fields with key
     * @param $application
     * @param $table
     * @return array
     */
    public function getTableFieldsWithKey($application, $table)
    {
        $fields = $this->getTableFields($application, $table);
        if ($this->getTableKey($application, $table) !== '') {
            $fields[] = $this->getTableKey($application, $table);
        }
        return $fields;
    }

    /**
     * Get satisfied application table by fields and key
     * @param $fields
     * @param $key
     * @return array
     */
    public function getTableSatisfied($fields, $key)
    {
        $res = [];
        foreach($this->getSupportedApplications() as $app) {
            foreach($this->getSupportedTables($app) as $table) {
                $config_fields = $this->getTableFieldsWithKey($app, $table);
                $config_key = $this->getTableKey($app, $table);
                if ($config_key === $key && empty(array_diff($fields, $config_fields))) {
                    $res[] = ['app' => $app, 'table' => $table];
                }
            }
        }
        return $res;
    }

    /**
     * Disable base64
     */
    public function disableBase64()
    {
        foreach($this->raw_config['applications'] as &$tables) {
            foreach($tables as &$table) {
                if (isset($table['base64']) && $table['base64'] === true) {
                    $table['base64'] = false;
                }
            }
            unset($table);
        }
        unset($tables);
    }

    /**
     * Check application defined in config
     * @param $app
     * @return bool
     */
    public function isApplicationDefined($app)
    {
        return isset($this->raw_config['applications'][$app]);
    }

    /**
     * Check table for application defined in config
     * @param $app
     * @param $table
     * @return bool
     */
    public function isTableDefined($app, $table)
    {
        return isset($this->raw_config['applications'][$app][$table]);
    }

    /**
     * @param $application
     * @param $table
     * @return array
     */
    public function getConfigForTable($application, $table)
    {
        return isset($this->raw_config['applications'][$application][$table]) ? $this->raw_config['applications'][$application][$table] : [];
    }

    /**
     * @param $application
     * @return string
     */
    public function getApplicationDomainQuery($application)
    {
        return isset($this->raw_config['applications'][$application]['domain_name']) ? $this->raw_config['applications'][$application]['domain_name'] : '';
    }
}
/**
 * Class MDSFindTables Find tables that we have in config
 */
class MDSFindTables
{
    private $db;
    private $config;

    public function __construct($db, MDSTablesConfig $config)
    {
        $this->db = $db;
        $this->config = $config;
    }

    public function find($db = null, $prefix = null)
    {
        $result = [];
        foreach ($this->config->getSupportedApplications() as $app)
        {
            foreach ($this->config->getSupportedTables($app) as $table) {
                $query = 'SELECT DISTINCT table_schema as db, table_name as tab '
                        . 'FROM information_schema.columns '
                        . 'WHERE column_name = \'' . $this->config->getTableKey($app, $table) . '\' AND column_key = \'PRI\'';
                if (isset($db)) {
                    $query .= ' AND table_schema = \'' . $db . '\'';
                }
                if (isset($prefix)) {
                    $query .= ' AND table_name LIKE \'' . $prefix . '%\'';
                }
                $fields = $this->config->getTableFields($app, $table);
                foreach($fields as $field) {
                    $query .= ' AND table_name IN (SELECT DISTINCT table_name FROM information_schema.columns WHERE column_name = \'' . $field . '\'';
                }
                $query .= str_repeat(')', count($fields));
                $query .= ';';
                $tables = $this->db->query($query);
                if ($tables->num_rows === 0) {
                    continue;
                }
                foreach($tables as $value) {
                    if (!isset($prefix)) {
                        $prefix = explode('_', $value['tab']);
                        $prefix = $prefix[0] . '_';
                    }
                    $domain_query = str_replace(['%db%', '%prefix%'], [$value['db'], $prefix], $this->config->getApplicationDomainQuery($app));
                    $domain_name_res = $this->db->query($domain_query);

                    $domain_name    = '';
                    $own_url        = '';
                    if ($domain_name_res && $domain_name_res->num_rows > 0) {
                        $row = @array_values($domain_name_res->fetch_row());
                        if (isset($row[0])) {
                            $own_url = $row[0];
                        }
                    }
                    if ($own_url) {
                        $domain_name = parse_url($own_url, PHP_URL_HOST);
                        $domain_name = preg_replace('~^www\.~ism', '', $domain_name);
                        $domain_name = strtolower($domain_name);
                    }

                    $result[] = [
                        'config_app'    => $app,
                        'config_tab'    => $table,
                        'db'            => $value['db'],
                        'table'         => $value['tab'],
                        'prefix'        => $prefix,
                        'domain_name'   => $domain_name,
                        'config'        => $this->config->getConfigForTable($app, $table),
                    ];
                }
            }
            return $result;
        }
    }
}

/**
 * Class MDSJSONReport need for prepare and wirte JSON report
 */
class MDSJSONReport
{
    const STATUS_DETECTED   = 'detected';
    const STATUS_CLEAN      = 'clean';
    const STATUS_RESTORE    = 'restore';

    const STATE_DONE        = 'done';
    const STATE_CANCELED    = 'canceled';

    private $start_time         = '';
    private $report_filename    = '';
    private $unknown_urls_send  = '';
    private $mds_version        = '';
    private $malware_db_version = '';
    private $db_host            = '';
    private $db_name            = '';
    private $db_username        = '';
    private $db_port            = 3306;

    private $report_scan        = [];
    private $report_clean       = [];
    private $report_url_scan    = [];
    private $report_url_clean   = [];

    private $report = [];
    private $report_url = [];
    private $unknown_urls = [];
    private $urls_counter = 0;

    private $table_total_rows = [];

    private $count_tables_scanned   = 0;
    private $running_time           = 0;
    private $errors                 = [];
    private $state                  = self::STATE_DONE;

    private $report_error           = null;

    private $uniq_tables_affected   = [];
    private $rows_infected          = 0;
    private $rows_cleaned           = 0;
    private $rows_restored          = 0;
    private $rows_with_errors       = [];

    private $count_of_detected_malicious_entries    = 0;
    private $count_of_cleaned_malicious_entries     = 0;
    private $operation = '';
    private $ch = null;

    private $app = null;
    private $app_owner_uid = null;
    private $path = null;
    private $scan_id = null;
    private $save_urls_limit = 5000;
    private $base64 = true;

    /**
     * MDSJSONReport constructor.
     * @param string $report_filename
     * @param string $mds_version
     * @param string $malware_db_version
     * @param string $db_host
     * @param string $db_name
     * @param string $db_username
     * @param string $db_port
     */
    public function __construct($start_time, $report_filename, $mds_version, $malware_db_version, $db_host, $db_name, $db_username, $db_port)
    {
        $this->start_time           = $start_time;
        $this->report_filename      = $report_filename;
        $this->mds_version          = $mds_version;
        $this->malware_db_version   = $malware_db_version;
        $this->db_host              = $db_host;
        $this->db_name              = $db_name;
        $this->db_username          = $db_username;
        $this->db_port              = $db_port;

        if (empty($report_filename) || (!file_exists($report_filename) && !is_writable(dirname($report_filename)))) {
            $this->report_error = new MDSException(MDSErrors::MDS_REPORT_ERROR, $report_filename);
        }
    }

    public function setSaveUrlsLimit($limit)
    {
        $this->save_urls_limit = $limit;
    }

    public function setMalwareDbVer($ver)
    {
        $this->malware_db_version = $ver;
    }

    public function setOp($op)
    {
        $this->operation = $op;
    }

    public function setApp($app)
    {
        $this->app = $app;
    }

    public function setAppOwnerUId($app_owner_uid)
    {
        $this->app_owner_uid = $app_owner_uid;
    }

    public function setPath($path)
    {
        $this->path = $path;
    }

    public function setScanId($scan_id)
    {
        $this->scan_id = $scan_id;
    }

    public function setCH($ch)
    {
        $this->ch = $ch;
    }

    public function getUser()
    {
        return $this->db_username;
    }

    public function getHost()
    {
        return $this->db_host;
    }


    public function getDbName()
    {
        return $this->db_name;
    }

    public function getError()
    {
        return $this->report_error;
    }

    /**
     * Set the total number of tables that we scanned
     * @param int $count
     * @return void
     */
    public function setCountTablesScanned($count)
    {
        $this->count_tables_scanned = $count;
    }

    /**
     * Set the total number of tables that we scanned
     * @param int $count
     * @return void
     */
    public function setUnknownUrlsSend($send_urls)
    {
        $this->unknown_urls_send = $send_urls;
    }

    /**
     * Set the total running time of the script
     * @param int $running_time_in_sec
     * @return void
     */
    public function setRunningTime($running_time_in_sec)
    {
        $this->running_time = $running_time_in_sec;
    }

    /**
     * Add total scanned rows for every table
     * @param string $table_name
     * @param int $count
     * @return void
     */
    public function addTotalTableRows($table_name, $count)
    {
        $this->table_total_rows[$table_name] = $count;
    }

    /**
     * Add error code and message
     * @param int $error_code
     * @param string $error_msg
     * @return void
     */
    public function addError($error_code, $error_msg)
    {
        $this->errors[] = [
            'code'      => $error_code,
            'message'   => $error_msg,
        ];
    }

    /**
     * Change state
     * @param string $state
     * @return void
     */
    public function setState($state)
    {
        $this->state = $state;
    }

    /**
     * Change base64 support
     * @param bool $base64
     */
    public function setBase64($base64)
    {
        $this->base64 = $base64;
    }

    /**
     * Add errors
     * @param array $errors
     * @return void
     */
    public function addErrors($errors)
    {
        $this->errors = $errors;
    }

    /**
     * Add detected info
     * @param string $signature_id
     * @param string $snippet
     * @param string $table_name
     * @param int $row_id
     * @return void
     */
    public function addDetected($signature_id, $snippet, $table_name, $row_id, $field = '')
    {
        $this->addSignatureRowId($signature_id, $snippet, $table_name, $row_id, $field, self::STATUS_DETECTED, $this->report_scan);
    }

    /**
     * Add detected info
     * @param string $signature_id
     * @param string $snippet
     * @param string $table_name
     * @param int $row_id
     * @return void
     */
    public function addDetectedUrl($signature_id, $snippet, $table_name, $row_id, $field = '')
    {
        $this->addSignatureRowId($signature_id, $snippet, $table_name, $row_id, $field, self::STATUS_DETECTED, $this->report_url_scan);
    }

    /**
     * @param $url
     */
    public function addUnknownUrl($url)
    {
        if (!isset($this->unknown_urls[$url])) {
            $this->unknown_urls[$url] = '';
            $this->urls_counter++;
        }

        if ($this->unknown_urls_send !== '' && $this->urls_counter >= $this->save_urls_limit) {
            $this->unknown_urls_send->send(array_keys($this->unknown_urls));
            $this->urls_counter = 0;
            $this->unknown_urls = [];
        }
    }

    /**
     * Add detected error info
     * @param string $signature_id
     * @param string $snippet
     * @param string $error_code
     * @return void
     */
    public function addDetectedError($signature_id, $snippet, $table_name, $row_id, $field, $error_code)
    {
        $this->addSignatureError($signature_id, $snippet, $table_name, $row_id, $field, $error_code, self::STATUS_DETECTED, $this->report);
    }

    /**
     * Add clean info
     * @param string $signature_id
     * @param string $snippet
     * @param string $table_name
     * @param int $row_id
     * @return void
     */
    public function addCleaned($signature_id, $snippet, $table_name, $row_id, $field = '')
    {
        $report = &$this->report_clean;
        if (strpos($signature_id, 'CMW-URL-') === 0) {
            $report = &$this->report_url_clean;
        }

        $this->addSignatureRowId($signature_id, $snippet, $table_name, $row_id, $field, self::STATUS_CLEAN, $report);
    }

    /**
     * Add clean error info
     * @param string $signature_id
     * @param string $snippet
     * @param string $error_code
     * @return void
     */
    public function addCleanedError($signature_id, $snippet, $table_name, $row_id, $field, $error_code)
    {
        $this->addSignatureError($signature_id, $snippet, $table_name, $row_id, $field, $error_code, self::STATUS_CLEAN, $this->report);
    }

    /**
     * Add restored info
     * @param string $table_name
     * @param int $row_id
     * @param string $field
     * @return void
     */
    public function addRestored($table_name, $row_id, $field = '')
    {
        $this->addSignatureRowId('', '', $table_name, $row_id, $field, self::STATUS_RESTORE, $this->report);
        $this->rows_restored++;
    }

    /**
     * Add restored error info
     * @param string $error_code
     * @return void
     */
    public function addRestoredError($error_code, $table_name, $row_id, $field = '')
    {
        $this->addSignatureError('', '', $table_name, $row_id, $field, $error_code, self::STATUS_RESTORE, $this->report);
    }

    /**
     * Save report
     * @return void
     */
    public function save()
    {
        $report = $this->prepareReport();
        $json = json_encode($report);
        file_put_contents($this->report_filename, $json);

        if ($this->unknown_urls_send !== '' && !empty($this->unknown_urls)) {
            $this->unknown_urls_send->send(array_keys($this->unknown_urls));
        }

        if(isset($this->ch)) {
            $this->ch->prepareData($report);
            $this->ch->send();
        }
    }

    // /////////////////////////////////////////////////////////////////////////

    /**
     * Prepare report data for save
     * @return array
     */
    private function prepareReport()
    {
        $tables_affected = [];
        if ($this->operation === MDSConfig::PARAM_SCAN) {
            $this->report = array_merge($this->report_scan, $this->report);
            $this->report_url = &$this->report_url_scan;
            $tables_affected = $this->uniq_tables_affected[self::STATUS_DETECTED] ?? [];
        } else if ($this->operation === MDSConfig::PARAM_CLEAN) {
            $this->report = array_merge($this->report_clean, $this->report);
            $this->report_url = &$this->report_url_clean;
            $tables_affected = $this->uniq_tables_affected[self::STATUS_CLEAN] ?? [];
        }

        $report =  [
            'start_time'                            => $this->start_time,
            'scanning_engine_version'               => $this->mds_version,
            'malware_database_version'              => $this->malware_db_version,
            'count_of_tables_scanned'               => $this->count_tables_scanned,
            'count_of_tables_affected'              => count($tables_affected),
            'count_of_rows_infected'                => $this->rows_infected,
            'count_of_rows_cleaned'                 => $this->rows_cleaned,
            'count_of_rows_restored'                => $this->rows_restored,
            'count_of_detected_malicious_entries'   => $this->count_of_detected_malicious_entries,
            'count_of_cleaned_malicious_entries'    => $this->count_of_cleaned_malicious_entries,
            'running_time'                          => $this->running_time,
            'error_list'                            => $this->errors,
            'database_host'                         => $this->db_host,
            'database_port'                         => $this->db_port,
            'database_name'                         => $this->db_name,
            'database_username'                     => $this->db_username,
            'detailed_reports'                      => $this->processReport($this->report),
            'detailed_urls_reports'                 => $this->processReport($this->report_url),
            'rows_with_error'                       => $this->rows_with_errors,
            'state'                                 => $this->state,
            'operation'                             => $this->operation,
            'app'                                   => $this->app,
            'app_owner_uid'                         => $this->app_owner_uid,
            'path'                                  => $this->path,
            'base64_sup'                            => $this->base64,
        ];
        if ($this->scan_id) {
            $report['scan_id'] = $this->scan_id;
        }
        return $report;
    }

    /**
     * @param array $report
     * @return array
     */
    private function processReport($report)
    {
        $reports = [];
        foreach ($report as $signature_id => $signature_params)
        {
            if (isset($signature_params['error'])) {
                $reports[] = [
                    'sigid'     => $signature_id,
                    'snpt'      => $signature_params['snippet'],
                    'status'    => 'error',
                    'errcode'   => $signature_params['error'],
                    'tables'    => [],
                ];
                continue;
            }
            $tables_result = [];
            foreach ($signature_params['tables_info'] as $table_name => $fields) {
                $fields_data = [];
                foreach ($fields as $field => $row_ids) {
                    $fields_data[] = [
                        'field'     => $field,
                        'row_ids'   => $row_ids,
                        'row_inf'   => count($row_ids),
                    ];
                }
                if ($fields_data) {
                    $tables_result[] = [
                        'table'         => $table_name,
                        'total_rows'    => isset($this->table_total_rows[$table_name]) ? $this->table_total_rows[$table_name] : 0,
                        'fields'        => $fields_data,
                    ];
                }
            }
            $reports[] = [
                'sigid'     => $signature_id,
                'snpt'      => $signature_params['snippet'],
                'status'    => $signature_params['status'],
                'tables'    => $tables_result,
                'errcode'   => 0,
            ];
        }
        return $reports;
    }

    /**
     * General method for adding detection and clean information
     * @param string $signature_id
     * @param string $snippet
     * @param string $table_name
     * @param string $row_id
     * @param string $status
     * @param array  &$report
     * @return void
     */
    private function addSignatureRowId($signature_id, $snippet, $table_name, $row_id, $field, $status = self::STATUS_DETECTED, &$report = null)
    {
        if ($this->initReportRow($signature_id, $snippet, $status, $report)) {
            if ($status == self::STATUS_DETECTED) {
                $this->count_of_detected_malicious_entries++;
            }
            elseif ($status == self::STATUS_CLEAN) {
                $this->count_of_cleaned_malicious_entries++;
            }
        }
        if (!isset($report[$signature_id]['tables_info'][$table_name])) {
            $report[$signature_id]['tables_info'][$table_name] = [];
        }
        if (!isset($report[$signature_id]['tables_info'][$table_name][$field])) {
            $report[$signature_id]['tables_info'][$table_name][$field] = [];
        }
        $report[$signature_id]['tables_info'][$table_name][$field][] = $row_id;
        if (!isset($this->uniq_tables_affected[$status][$table_name][$field][$row_id])) {
            if ($status === self::STATUS_DETECTED) {
                $this->rows_infected++;
            }
            elseif ($status === self::STATUS_CLEAN) {
                $this->rows_cleaned++;
            }
        }
        $this->uniq_tables_affected[$status][$table_name][$field][$row_id] = '';
    }

    /**
     * General method for adding detection and clean error information
     * @param string $signature_id
     * @param string $snippet
     * @param string $error_code
     * @param string $status
     * @param array &$report
     * @return void
     */
    private function addSignatureError($signature_id, $snippet, $table_name, $row_id, $field, $error_code, $status = self::STATUS_DETECTED, &$report = null)
    {
        $this->initReportRow($signature_id, $snippet, $status, $report);
        $report[$signature_id]['error'] = $error_code;
        if (!isset($this->rows_with_errors['tables_info'][$table_name])) {
            $this->rows_with_errors['tables_info'][$table_name] = [];
        }
        if (!isset($this->rows_with_errors['tables_info'][$table_name][$field])) {
            $this->rows_with_errors['tables_info'][$table_name][$field] = [];
        }
        $this->rows_with_errors['tables_info'][$table_name][$field][] = $row_id;
    }

    /**
     * Initiate an array element if not exists
     * @param string $signature_id
     * @param string $snippet
     * @param string $status
     * @param array &$report
     * @return void
     */
    private function initReportRow($signature_id, $snippet, $status = self::STATUS_DETECTED, &$report = null)
    {
        if (isset($report[$signature_id])) {
            return false;
        }
        $report[$signature_id] = [
            'snippet'       => $snippet,
            'total_rows'    => 0,
            'status'        => $status,
            'rows_infected' => 0,
            'tables_info'   => [],
            'error'         => null,
        ];
        return true;
    }
}

/**
 * Class MDSProgress module for tracking progress
 */
class MDSProgress
{
    private $total;
    private $total_table;
    private $num_tables = 1;
    private $current_table;
    private $current_table_num;
    private $current_db;
    private $current_db_num;
    private $last_file_update = 0;
    private $last_update = 0;
    private $progress_file;
    private $shared_mem;
    private $create_shared_mem;
    private $file_write_interval;
    private $update_interval;
    private $start;
    private $progress_string;
    private $tables;
    private $last_table_key;
    private $first_table_key;
    private $print = null;
    private $percent_main;
    private $db_count = 1;
    private $percent_table;

    private $one_db_percent;
    private $one_table_percent;
    private $one_record_percent;

    /**
     * MDSProgress constructor.
     * @param string $file - file for writing progress
     * @param int $update_interval - interval for update progress
     * @param int $file_write_interval - interval for writing to file progress
     * @param int $shared_mem - write to shared memory
     * @param bool $need_create_shmem - need to create shared memory
     * @throws Exception
     */
    public function __construct($file = false, $update_interval = 0, $file_write_interval = 1, $shared_mem = false, $need_create_shmem = false)
    {
        $this->start = time();
        $this->update_interval = $update_interval;
        $this->file_write_interval = $file_write_interval;
        if ($shared_mem) {
            $this->create_shared_mem = $need_create_shmem;
            if ($this->create_shared_mem) {
                @$this->shared_mem = new SharedMem((int)$shared_mem, "n", 0600, 5000);
            } else {
                @$this->shared_mem = new SharedMem((int)$shared_mem, "w", 0, 0);
            }
            if (!$this->shared_mem->isValid()) {
                if ($need_create_shmem) {
                    throw new MDSException(MDSErrors::MDS_PROGRESS_SHMEM_CRT_ERROR, $shared_mem);
                } else {
                    throw new MDSException(MDSErrors::MDS_PROGRESS_SHMEM_ERROR, $shared_mem);
                }
            }
        }

        if ($file) {
            if (is_writable(dirname($file)) || (file_exists($file) && is_writable($file))) {
                $this->progress_file = $file;
            } else {
                throw new MDSException(MDSErrors::MDS_PROGRESS_FILE_ERROR, $file);
            }
        }
    }

    /**
     * @param $total - total records for scanning
     */
    public function setTotal($total)
    {
        $this->total = $total;
    }

    /**
     * @param $num_dbs - num of tables for scan
     */
    public function setDbCount($num_dbs)
    {
        $this->db_count = $num_dbs;
        $this->one_db_percent = $num_dbs ? 100 / $num_dbs : 0;
    }

    /**
     *
     */
    public function getDbCount()
    {
        return $this->db_count;
    }

    /**
     * @param $tables - array of tables for scan
     */
    public function setTables($tables)
    {
        $this->tables = $tables;
        $this->num_tables = count($tables);
        $this->one_table_percent = $this->one_db_percent / $this->num_tables;
    }

    /**
     * @param $print - print function to printout progress
     */
    public function setPrint($print)
    {
        $this->print = $print;
    }

    /**
     * @param $i - index of currently scanned table
     * @param $table - name of currently scanned table
     */
    public function setCurrentTable($i, $table)
    {
        $new_percent = number_format(($this->current_db_num * $this->one_db_percent) + ($i * $this->one_table_percent), 1);
        $this->progress_string = str_replace(substr($this->progress_string, 0, strpos($this->progress_string, '% of whole scan')), '[' . ($i + 1) . '/' . $this->num_tables . ' tbls of ' . ($this->current_db_num + 1) . '/' . $this->db_count . ' dbs] ' . $new_percent, $this->progress_string);
        $this->current_table_num = $i;
        $this->current_table = $table;
        $this->percent_main = $new_percent;
        if ($this->print !== null && is_callable($this->print)) {
            $this->print->call($this, $this->getProgressAsString());
        }
    }

    /**
     * @param $i - index of currently scanned table
     * @param $table - name of currently scanned table
     */
    public function setCurrentDb($i, $db)
    {
        $new_percent = number_format($i * $this->one_db_percent, 1);
        $this->progress_string = str_replace(substr($this->progress_string, 0, strpos($this->progress_string, '% of whole scan')), '[' . ($this->current_table_num + 1) . '/' . $this->num_tables . ' tbls of ' . ($i + 1) . '/' . $this->db_count . ' dbs] ' . $new_percent, $this->progress_string);
        $this->current_db_num = $i;
        $this->current_db = $db;
        $this->percent_main = $new_percent;
        if ($this->print !== null && is_callable($this->print)) {
            $this->print->call($this, $this->getProgressAsString());
        }
    }

    /**
     * @param $key_start - first key of table
     * @param $key_last - last key of table
     */
    public function setKeysRange($key_start, $key_last)
    {
        $this->first_table_key = $key_start;
        $this->last_table_key = $key_last;
        $this->setTotalTable(($key_last - $key_start) + 1);
    }

    /**
     * @param $total_table - total records for table
     */
    public function setTotalTable($total_table)
    {
        $this->total_table = $total_table;
        $this->one_record_percent = $this->one_table_percent / $this->total_table;
    }

    /**
     * @param $row_id - current record
     * @param $detected - num of detected malicious
     * @param $db - current db
     * @param $table - current table
     */
    public function updateProgress($row_id, $detected, $cleaned, $db, $table)
    {
        if (time() - $this->last_update < $this->update_interval) {
            return;
        }

        $corrected_start_value = $row_id - $this->first_table_key;
        $percent_table = number_format($this->total_table ? $corrected_start_value * 100 / $this->total_table : 0, 1);
        $elapsed_time    = microtime(true) - $this->start;

        $stat            = '';
        $left            = 0;
        $left_time       = 0;
        $elapsed_seconds = 0;

        $percent_main = $this->percent_main;

        $percent_main += number_format($corrected_start_value * $this->one_record_percent, 1);

        if ($elapsed_time >= 1) {
            $elapsed_seconds = round($elapsed_time, 0);
            $fs              = floor($corrected_start_value / $elapsed_seconds);
            $left            = $this->total_table - $corrected_start_value;
            $clean = ($cleaned > 0 ? '/' . $cleaned : '');
            $malware = ($detected > 0 ? '[Mlw:' . $detected . $clean . ']' : '');
            if ($fs > 0) {
                $left_time = ($left / $fs);
                $stat = ' [Avg: ' . round($fs, 2) . ' rec/s' . ($left_time > 0 ? ' Left: ' . AibolitHelpers::seconds2Human($left_time) . ' for current table' : '') . '] ' . $malware;
            }
        }

        $this->progress_string = '[' . ($this->current_table_num + 1) . '/' . $this->num_tables . ' tbls of ' . ($this->current_db_num + 1) . '/' . $this->db_count . ' dbs] ' . $percent_main . '% of whole scan' . '/' . $percent_table . '% [' . $db . '.' . $table . '] ' . $corrected_start_value . ' of ' . $this->total_table . ' rows ' . $stat;

        $data = [
            'self'                  => __FILE__,
            'started'               => $this->start,
            'updated'               => time(),
            'progress_table'        => $percent_table,
            'progress_main'         => $percent_main,
            'time_elapsed'          => $elapsed_seconds,
            'time_left'             => round($left_time),
            'left'                  => $left,
            'total_table'           => $this->total_table,
            'current_index'         => $corrected_start_value,
            'current_db_num'        => $this->current_db_num,
            'current_table_num'     => $this->current_table_num,
            'total_db_count'        => $this->db_count,
            'total_tbl_db_count'    => $this->num_tables,
            'current_row_id'        => $row_id,
            'current'               => $db . '.' . $table . '/' . $row_id,
        ];

        if ($this->progress_file && (time() - $this->last_file_update > $this->file_write_interval)) {
            if (function_exists('json_encode')) {
                file_put_contents($this->progress_file, json_encode($data));
            } else {
                file_put_contents($this->progress_file, serialize($data));
            }

            $this->last_file_update = time();
        }

        if ($this->shared_mem && $this->shared_mem->isValid()) {
            $this->shared_mem->write($data);
        }

        if ($this->print !== null && is_callable($this->print)) {
            $this->print->call($this, $this->getProgressAsString());
        }
    }

    /**
     * @return string
     */
    public function getProgressAsString()
    {
        return $this->progress_string;
    }

    public function finalize()
    {
        if ($this->progress_file && file_exists($this->progress_file)) {
            @unlink($this->progress_file);
        }
        if ($this->shared_mem && $this->shared_mem->isValid()) {
            $this->shared_mem->close($this->create_shared_mem);
        }
        $this->shared_mem = null;
    }
}
/**
 * Class MDSScan module for scan string with signatures
 */
class MDSScan
{
    /**
     * Scan function
     * @param $content
     * @param $signature_db
     * @return array|bool
     */
    public static function scan($content, $signature_db, $table_config)
    {
        $checkers['CriticalPHP'] = true;
        $checkers['CriticalJS'] = true;

        $checker_url['UrlChecker'] = false;

        $result = [];
        $resultUrl = [];

        $processResult = function ($checker, $content, $l_Pos, $l_SigId, &$return) use (&$result, $signature_db) {
            $return = null;
            $result = [
                'content' => self::getFragment($content, $l_Pos),
                'pos' => $l_Pos,
                'sigid' => $l_SigId,
            ];
            if (isset($l_SigId) && isset($signature_db->_Mnemo[$l_SigId])) {
                $result['sn'] = $signature_db->_Mnemo[$l_SigId];
            } else {
                $result['sn'] = '';
            }
        };

        $processUrlResult = function ($checker, $content, $l_Pos, $l_SigId, &$return) use (&$resultUrl, $signature_db) {
            $return = null;
            if (isset($l_Pos['black'])) {
                for ($i=0, $iMax = count($l_Pos['black']); $i < $iMax; $i++) {
                    $resultUrl['black'][] = [
                        'content' => self::getFragment($content, $l_Pos['black'][$i]),
                        'pos' => $l_Pos['black'][$i],
                        'sigid' => $l_SigId['black'][$i],
                    ];
                }
            }

            if (isset($l_Pos['unk'])) {
                for ($i=0, $iMax = count($l_Pos['unk']); $i < $iMax; $i++) {
                    $resultUrl['unk'][] = [
                        'content' => self::getFragment($content, $l_Pos['unk'][$i]),
                        'pos' => $l_Pos['unk'][$i],
                        'sigid' => $l_SigId['unk'][$i],
                    ];
                }
            }
        };

        $l_Unwrapped = $content;
        if (isset($table_config['escaped']) && $table_config['escaped'] === true) {
            $l_Unwrapped = Normalization::unescape($l_Unwrapped);
        }
        $l_Unwrapped = Normalization::strip_whitespace($l_Unwrapped);
        $l_UnicodeContent = Encoding::detectUTFEncoding($content);
        if ($l_UnicodeContent !== false && Encoding::iconvSupported()) {
            $l_Unwrapped = Encoding::convertToCp1251($l_UnicodeContent, $l_Unwrapped);
        }
        $l_DeobfObj = new Deobfuscator($l_Unwrapped, $content);
        $l_DeobfType = $l_DeobfObj->getObfuscateType($l_Unwrapped);
        if ($l_DeobfType !== '') {
            $l_Unwrapped = $l_DeobfObj->deobfuscate();
        }

        $l_Unwrapped = Normalization::normalize($l_Unwrapped);
        $found = ScanUnit::QCR_ScanContent($checkers, $l_Unwrapped, $content, $signature_db, null, null, $processResult);
        $found_urls = ScanUnit::QCR_ScanContent($checker_url, $l_Unwrapped, $content, $signature_db, null, null, $processUrlResult);
        $ret = false;
        if ($found) {
            $ret['mlw'] = $result;
        }
        if ($found_urls) {
            $ret['url'] = $resultUrl;
        }
        return $ret;
    }

    public static function scanBatch($list, $signature_db, $table_config)
    {
        foreach($list->getEntriesForScan() as $k => $v) {
            if ($res = self::scan($v->getB64decodedContent() ?? $v->getContent(), $signature_db, $table_config)) {
                $list->addScanResult($k, $res);
            }
        }
    }

    /**
     * Get snippet from string
     * @param $par_Content
     * @param $par_Pos
     * @return string|string[]
     */
    private static function getFragment($par_Content, $par_Pos)
    {
        $l_MaxChars = 120;

        $par_Content = preg_replace('/[\x00-\x1F\x80-\xFF]/', '~', $par_Content);

        $l_MaxLen   = strlen($par_Content);
        $l_RightPos = min($par_Pos + $l_MaxChars, $l_MaxLen);
        $l_MinPos   = max(0, $par_Pos - $l_MaxChars);

        $l_Res = ($l_MinPos > 0 ? '…' : '') . substr($par_Content, $l_MinPos, $par_Pos - $l_MinPos) . '__AI_MARKER__' . substr($par_Content, $par_Pos, $l_RightPos - $par_Pos - 1);

        $l_Res = AibolitHelpers::makeSafeFn(Normalization::normalize($l_Res));

        $l_Res = str_replace('~', ' ', $l_Res);

        $l_Res = preg_replace('~[\s\t]+~', ' ', $l_Res);

        $l_Res = str_replace('' . '?php', '' . '?php ', $l_Res);

        return $l_Res;
    }
}
/**
 * Class MDSPreScanQuery generates PreScan SQL Query to get suspicious rows
 */
class MDSPreScanQuery
{
    private $aliases = [];
    private $limit = 0;
    private $last = 0;
    private $key;
    private $table;
    private $fields;
    private $prescan;
    private $b64_template;

    /**
     * MDSPreScanQuery constructor.
     * @param $prescan
     * @param $fields
     * @param $key
     * @param $table
     * @param $db
     * @param int $limit
     * @param int $last
     */
    public function __construct($prescan, $fields, $key, $table, $db, $limit = 0, $last = 0)
    {
        $this->b64_template = 'CHAR_LENGTH($$FF$$) % 4 = 0 AND $$FF$$ REGEXP \'^[-A-Za-z0-9+/]*={0,3}$\'';
        $this->limit = $limit;
        $this->prescan = $prescan;
        $this->fields = $fields;
        $this->key = $key;
        $this->table = $table;
        $this->last = $last;
        $this->db = $db;
        $this->generateAliases();
    }

    /**
     * @return array
     */
    public function getAliases()
    {
        return $this->aliases;
    }

    /**
     * @param $alias
     * @return bool|string
     */
    public function getFieldByAlias($alias)
    {
        foreach ($this->aliases as $key => $field) {
            if ($field === $alias) {
                return $key;
            }
        }
        return false;
    }

    /**
     * @param $value
     */
    public function setLastKey($value)
    {
        $this->last = $value;
    }

    /**
     * @return int
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * @return string
     */
    public function getDB()
    {
        return $this->db;
    }

    /**
     * @return string
     */
    public function getTable()
    {
        return $this->table;
    }

    /**
     * Generate pre scan sql query with base64 checking
     * @return string
     */
    public function generateSqlQueryWithBase64()
    {
        $res = 'SELECT ';
        $numItems = count($this->aliases);
        $i = 0;
        foreach($this->aliases as $column => $alias) {
            $res .= '`' . $column . '`' . ' as ' . $alias;
            if ($alias === 'mds_key') {
                break;
            }
            $res .= str_replace('$$FF$$', '`' . $column . '`', ', IF (' . $this->prescan . ', 1, 0) as ' . $alias . '_norm');
            $res .= str_replace('$$FF$$', 'FROM_BASE64(`' . $column . '`)', ', IF (' . $this->prescan . ', 1, 0) as ' . $alias . '_b64');
            if(++$i !== $numItems) {
                $res .= ',';
            }
        }
        $res .= ' FROM `' . $this->db . '`.`' . $this->table . '`';
        $res .= ' WHERE `' . $this->key . '` > ' . $this->last;
        $res .= ' AND ';
        $res .= ' (';
        $res .= '(' . $this->generatePreScanClause() . ')';
        $res .= ' OR (' . $this->generatePreScanClause(true) . ')';
        $res .= ')';
        $res .= ' HAVING ';
        $i = 0;
        foreach($this->aliases as $alias) {
            if ($alias === 'mds_key') {
                break;
            }
            $res .= $alias . '_norm = 1' . ' OR ' . $alias . '_b64 = 1';
            if(++$i !== $numItems - 1) {
                $res .= ' OR ';
            }
        }
        $res .= ' ORDER BY `' . $this->key . '`';
        if ($this->limit > 0) {
            $res .= ' LIMIT ' . $this->limit;
        }
        $res .= ';';
        return $res;
    }

    /**
     * Generate pre scan sql query
     * @return string
     */
    public function generateSqlQuery()
    {
        $res = 'SELECT ';
        $numItems = count($this->aliases);
        $i = 0;
        foreach($this->aliases as $column => $alias) {
            $res .= '`' . $column . '` as ' . $alias;
            if(++$i !== $numItems) {
                $res .= ',';
            }
        }
        $res .= ' FROM `' . $this->db . '`.`' . $this->table . '`';
        $res .= ' WHERE `' . $this->key . '` > ' . $this->last;
        $res .= ' AND (' . $this->generatePreScanClause() . ')';
        $res .= ' ORDER BY `' . $this->key . '`';
        if ($this->limit > 0) {
            $res .= ' LIMIT ' . $this->limit;
        }
        $res .= ';';
        return $res;
    }

    /**
     * generate aliases for fields
     */
    private function generateAliases()
    {
        $alphabet = 'abcdefghijklmnopqrstuvwxyz';
        $fields = $this->fields;
        $res = [];
        for ($i = 0, $iMax = count($fields); $i < $iMax; $i++) {
            $res[$fields[$i]] = $alphabet[$i];
        }
        $res[$this->key] = 'mds_key';
        $this->aliases = $res;
    }


    /**
     * Generate where clause part for sql pre scan query
     * @return string
     */
    private function generatePreScanClause($base64 = false)
    {
        $template = $base64 ? $this->b64_template : $this->prescan;
        $res = '';
        for ($i = 0, $iMax = count($this->fields); $i < $iMax; $i++) {
            $res .= str_replace('$$FF$$', '`' . $this->fields[$i] . '`', '(' . $template . ')');
            if ($i !== $iMax - 1) {
                $res .= ' OR ';
            }
        }
        return $res;
    }
}

/**
 * Class MDSScannerTable module for scan whole table
 */
class MDSScannerTable
{
    /**
     * @param mysqli            $connection
     * @param MDSPreScanQuery   $query
     * @param array             $signature_db
     * @param int               $max_clean
     * @param array             $clean_db
     * @param MDSProgress       $progress
     * @param MDSState          $state
     * @param MDSJSONReport     $report
     * @param MDSBackup         $backup
     * @param Logger            $log
     * @throws Exception
     */
    public static function scan($connection, $query, $signature_db, $max_clean, $clean_db = null, $progress = null, $state = null, $report = null, $backup = null, $log = null, $table_config = null)
    {
        $total_scanned = 0;
        $detected = 0;
        $detected_url = 0;
        $cleaned = 0;
        $list = new MDSProcessingList();
        list($min_key, $last_key) = $connection->query('SELECT MIN(`' . $query->getKey() .'`) as start_key, MAX(`' . $query->getKey() .'`) as last_key FROM `' . $query->getDB() . '`.`' . $query->getTable() . '`;')->fetch_array(MYSQLI_NUM);
        if ($progress instanceof MDSProgress) {
            $progress->setKeysRange($min_key, $last_key);
        }
        $pre_query = (isset($table_config['base64']) && $table_config['base64'] === true) ? $query->generateSqlQueryWithBase64() : $query->generateSqlQuery();
        $res = $connection->query($pre_query);
        if (self::isCanceled($state)) {
            $log->info('Task canceled');
            $report->setState(MDSJSONReport::STATE_CANCELED);
            return;
        }
        while($res && $res->num_rows > 0) {
            if (!isset($clean_db)) {
                foreach ($res as $row) {
                    if (self::isCanceled($state)) {
                        $log->info('Task canceled in progress');
                        $report->setState(MDSJSONReport::STATE_CANCELED);
                        return;
                    }
                    $list->addToList($row, $query);
                    $list->markAllEntriesForScan();
                    foreach($list->getEntriesForScan() as $k => $v) {
                        $result = MDSScan::scan($v->getB64decodedContent() ?? $v->getContent(), $signature_db, $table_config);
                        $list->addScanResult($k, $result);
                        if ($v->getScan() && $v->getScan()->IsMalwareDetected()) {
                            $log->debug(
                                sprintf(
                                    'DETECTED. Field: "%s", ID: %d, sn: "%s", content: "%s"',
                                    $v->getField(),
                                    $v->getKey(),
                                    $v->getScan()->getMalwareRes()->getSigname(),
                                    $v->getScan()->getMalwareRes()->getSnippet()
                                )
                            );
                            if ($report !== null) {
                                $report->addDetected(
                                    $v->getScan()->getMalwareRes()->getSigname(),
                                    $v->getScan()->getMalwareRes()->getSnippet(),
                                    $query->getTable(),
                                    $v->getKey(),
                                    $v->getField()
                                );
                            }
                            $detected++;
                        }
                        if ($v->getScan() && $v->getScan()->IsBlackUrlDetected()) {
                            foreach($v->getScan()->getBlackUrls() as $url) {
                                $log->debug(
                                    sprintf(
                                        'DETECTED Black Url. Field: "%s", ID: %d, sn: "%s", content: "%s"',
                                        $v->getField(),
                                        $v->getKey(),
                                        $url->getSigid(),
                                        $url->getSnippet()
                                    )
                                );
                                if ($report !== null) {
                                    $report->addDetectedUrl(
                                        $url->getSigid(),
                                        $url->getSnippet(),
                                        $query->getTable(),
                                        $v->getKey(),
                                        $v->getField()
                                    );
                                }
                                $detected_url++;
                            }
                        }
                        if ($v->getScan() && $v->getScan()->IsUnknownUrlDetected()) {
                            foreach($v->getScan()->getUnknownUrls() as $url) {
                                $log->debug(
                                    sprintf(
                                        'DETECTED Unknown Url. Field: "%s", ID: %d, sn: "%s", content: "%s"',
                                        $v->getField(),
                                        $v->getKey(),
                                        $url->getSigid(),
                                        $url->getSnippet()
                                    )
                                );
                                if ($report !== null) {
                                    $report->addUnknownUrl($url->getSigid());
                                }
                            }
                        }
                        $total_scanned++;
                        if ($progress instanceof MDSProgress) {
                            $progress->updateProgress($v->getKey(), $detected + $detected_url, 0, $query->getDB(), $query->getTable());
                        }
                        $query->setLastKey($v->getKey());
                    }
                    $list->clear();
                }
            } else {
                $i = $max_clean;
                while (true) {
                    $row = $res->fetch_assoc();
                    if ($i-- && $row) {
                        $list->addToList($row, $query);
                        continue;
                    } else if (!$row && $list->isEmpty()) {
                        break;
                    }
                    if ($row) {
                        $list->addToList($row, $query);
                    }
                    $list->markAllEntriesForScan();
                    $query->setLastKey($list->getLastKey());
                    MDSScan::scanBatch($list, $signature_db, $table_config);
                    foreach ($list->getEntriesWithScanResults() as $index => $entry) {
                        if (self::isCanceled($state)) {
                            $report->setState(MDSJSONReport::STATE_CANCELED);
                            return;
                        }
                        if (($entry->getScan() && $entry->getScan()->IsMalwareDetected()) || $entry->getScan()->IsBlackUrlDetected()) {
                            $list->addForClean($index);
                        }
                        if ($entry->getScan() && $entry->getScan()->IsMalwareDetected()) {
                            $log->debug(
                                sprintf(
                                    'DETECTED. Field: "%s", ID: %d, sn: "%s", content: "%s"',
                                    $entry->getField(),
                                    $entry->getKey(),
                                    $entry->getScan()->getMalwareRes()->getSigname(),
                                    $entry->getScan()->getMalwareRes()->getSnippet()
                                )
                            );
                            if ($report !== null) {
                                $report->addDetected(
                                    $entry->getScan()->getMalwareRes()->getSigname(),
                                    $entry->getScan()->getMalwareRes()->getSnippet(),
                                    $query->getTable(),
                                    $entry->getKey(),
                                    $entry->getField()
                                );
                            }
                            $detected++;
                        }
                        if ($entry->getScan() && $entry->getScan()->isBlackUrlDetected()) {
                            foreach($entry->getScan()->getBlackUrls() as $url) {
                                $log->debug(
                                    sprintf(
                                        'DETECTED Black Url. Field: "%s", ID: %d, sn: "%s", content: "%s"',
                                        $entry->getField(),
                                        $entry->getKey(),
                                        $url->getSigid(),
                                        $url->getSnippet()
                                    )
                                );
                                if ($report !== null) {
                                    $report->addDetectedUrl(
                                        $url->getSigid(),
                                        $url->getSnippet(),
                                        $query->getTable(),
                                        $entry->getKey(),
                                        $entry->getField()
                                    );
                                }
                                $detected_url++;
                            }
                        }
                        if ($entry->getScan() && $entry->getScan()->IsUnknownUrlDetected()) {
                            foreach ($entry->getScan()->getUnknownUrls() as $url) {
                                $log->debug(
                                    sprintf(
                                        'DETECTED Unknown Url. Field: "%s", ID: %d, sn: "%s", content: "%s"',
                                        $entry->getField(),
                                        $entry->getKey(),
                                        $url->getSigid(),
                                        $url->getSnippet()
                                    )
                                );
                                if ($report !== null) {
                                    $report->addUnknownUrl($url->getSigid());
                                }
                            }
                        }
                    }
                    if ($backup instanceof MDSBackup) {
                        foreach ($list->getEntriesWithScanResultsOnlyBlack() as $index => $entry) {
                            $backup->backup($query->getDB(), $query->getTable(), $entry->getField(), $query->getKey(), $entry->getKey(), $entry->getContent());
                        }
                    }
                    MDSCleanup::cleanBatch($list, $detected + $detected_url, $cleaned, $clean_db, $connection, $query, $progress, $table_config);
                    foreach ($list->getEntriesWithCleanErrors() as $index => $entry) {
                        $report->addCleanedError('', '', $query->getTable(), $entry->getKey(), $entry->getField(), MDSErrors::MDS_CLEANUP_ERROR);
                    }

                    foreach ($list->getEntriesWithCleanResults() as $index => $entry) {
                        foreach ($entry->getClean() as $sig) {
                            $log->debug(
                                sprintf('CLEANED. Field: "%s", ID: %d, sn: %s', $entry->getField(), $entry->getKey(),
                                    $sig)
                            );
                            $report->addCleaned($sig, $entry->getScan()->getSnippet(),
                                $query->getTable(), $entry->getKey(), $entry->getField());
                        }
                    }
                    $total_scanned += $list->getCount();
                    if ($progress instanceof MDSProgress) {
                        $progress->updateProgress($list->getLastKey(), $detected + $detected_url, $cleaned, $query->getDB(), $query->getTable());
                    }
                    $i = $max_clean;
                    $list->clear();
                }
            }
            $pre_query = (isset($table_config['base64']) && $table_config['base64'] === true) ? $query->generateSqlQueryWithBase64() : $query->generateSqlQuery();
            $res = $connection->query($pre_query);
        }

        $log->info(
            sprintf(
                'Scanning table "%s" finished. Scanned: %d, Detected: %d threats (%d signature and %d URL) in %d unique rows, Cleaned: %d unique rows',
                $query->getTable(),
                $total_scanned,
                $detected + $detected_url,
                $detected,
                $detected_url,
                $list->getCountKeysWithScanResultsOnlyBlack(),
                $cleaned
            )
        );

        if ($report !== null) {
            $report->addTotalTableRows($query->getTable(), $total_scanned);
        }

        if ($res === false) {
            $log->error('Error with db connection ' . $connection->error);
            throw new MDSException(MDSErrors::MDS_DROP_CONNECT_ERROR, $connection->error);
        }
    }

    /**
     * Check on cancel
     * @param MDSState  $state
     * @return bool
     */
    private static function isCanceled($state)
    {
        if (is_null($state)) {
            return false;
        }
        return $state->isCanceled();
    }
}

/**
 * Class MDSScanner module for scan whole user
 */
class MDSScanner
{
    /**
     * @param string                $prescan - prescan string
     * @param string                $database - db name (null to scan all dbs that user have access to)
     * @param string                $prefix - prefix (null to disable filter by prefix)
     * @param MDSFindTables         $mds_find
     * @param mysqli                $connection
     * @param LoadSignaturesForScan $scan_signatures
     * @param int                   $max_clean
     * @param array                 $clean_db
     * @param MDSProgress           $progress
     * @param MDSState              $state
     * @param MDSJSONReport         $report
     * @param MDSBackup             $backup
     * @param bool                  $scan
     * @param bool                  $clean
     * @param Logger $log
     * @throws Exception
     */
    public static function scan($prescan, $database, $prefix, $mds_find, $connection, $scan_signatures, $max_clean = 100, $clean_db = null, $progress = null, $state = null, $report = null, $backup = null, $scan = true, $clean = false, $log = null)
    {

        $start_time = microtime(true);

        $tables = $mds_find->find($database, $prefix);
        if (empty($tables)) {
            $log->error('Not found any supported tables. Nothing to scan.');
            throw new MDSException(MDSErrors::MDS_NO_SUP_TABLES_ERROR, $database, $report->getUser(), $report->getHost());
        }

        if ($progress instanceof MDSProgress) {
            $progress->setTables($tables);
        }

        if (!$scan && !$clean) {
            return;
        }

        $log->info('MDS Scan: started');

        if ($progress instanceof MDSProgress) {
            $progress->setCurrentTable(0, $tables[0]);
        }
        
        foreach($tables as $i => $table) {
            $scan_signatures->setOwnUrl($table['domain_name']);
            $prescan_query = new MDSPreScanQuery($prescan, $table['config']['fields'], $table['config']['key'], $table['table'], $table['db'], 10000);

            $log->debug(sprintf('Scanning table: "%s"', $table['table']));
            MDSScannerTable::scan($connection, $prescan_query, $scan_signatures, $max_clean, $clean_db, $progress, $state, $report, $backup, $log, $table['config']);
            if ($progress instanceof MDSProgress) {
                $progress->setCurrentTable($i, $table);
            }
        }
        
        if ($report !== null) {
            $report->setCountTablesScanned(count($tables));
            $report->setRunningTime(microtime(true) - $start_time);
        }

        $log->info(sprintf('MDS Scan: finished. Time taken: %f second(s)', microtime(true) - $start_time));

        if ($progress instanceof MDSProgress) {
            $progress->finalize();
        }

        if ($backup instanceof MDSBackup) {
            $backup->finish();
        }
    }
}
/**
 * The MDSState class is needed to pass the MDS state of work
 */
class MDSState
{
    private $cache_ttl              = 1; //sec
    private $cache_data             = null;
    private $last_update_time_cache = 0;
    
    const STATE_NEW         = 'new';
    const STATE_WORKING     = 'working';
    const STATE_DONE        = 'done';
    const STATE_CANCELED    = 'canceled';

    private $state_filepath = null;
   
    /**
     * MDSState constructor.
     * @param string $state_filepath
     * @param int $cache_ttl
     */
    public function __construct($state_filepath, $cache_ttl = 1)
    {
        $this->state_filepath   = $state_filepath;
        $this->cache_ttl        = $cache_ttl;
    }
    
    /**
     * Scan or cure process not started
     * @return bool
     */
    public function isNew()
    {
        return $this->getCurrentState() == self::STATE_NEW;
    }
    
    /**
     * The scan or cure process is currently running
     * @return bool
     */
    public function isWorking()
    {
        return $this->getCurrentState() == self::STATE_WORKING;
    }

    /**
     * The scan or cure process is canceled
     * @return bool
     */
    public function isCanceled()
    {
        return $this->getCurrentState() == self::STATE_CANCELED;
    }
    
    /**
     * The scan or cure process is done
     * @return bool
     */
    public function isDone()
    {
        return $this->getCurrentState() == self::STATE_DONE;
    }

    /**
     * Set process to work state
     * @return bool
     */
    public function setWorking()
    {
        return $this->setStateWithoutCheck(self::STATE_WORKING);
    }

    /**
     * Set process to done state
     * @return bool
     */
    public function setDone()
    {
        return $this->setStateWithoutCheck(self::STATE_DONE);
    }

    /**
     * Set process to canceled state
     * @return bool
     */
    public function setCanceled()
    {
        $func = function($data) {
            return ($data == self::STATE_WORKING) ? self::STATE_CANCELED : $data;
        };
        $new_data = $this->editFileWithClosure($this->state_filepath, $func);
        $this->setCache($new_data);
        return $new_data == self::STATE_CANCELED;
    }
    
    // /////////////////////////////////////////////////////////////////////////

    /**
     * Overwrite the file with new data with the condition programmed in the closure
     * @param string $filepath
     * @param function $edit_func
     * @param mixed $default
     * @return mixed
     */
    private function editFileWithClosure($filepath, $edit_func, $default = null)
    {
        $result = $default;
        $fh     = @fopen($filepath, 'c+');
        if (!$fh) {
            return $result;
        }
        if (flock($fh, LOCK_EX)) {
            $data   = trim(stream_get_contents($fh));
            $result = $edit_func($data);
            
            fseek($fh, 0);
            ftruncate($fh, 0);
            fwrite($fh, $result);
        }
        else {
            fclose($fh);
            return $result;
        }
        fclose($fh);
        return $result;
    }

    /**
     * Get file data
     * @param string $filepath
     * @return string|bool
     */
    private function readFile($filepath)
    {
        if (!file_exists($filepath)) {
            $this->setCache(false);
            return false;
        }
        $fh = @fopen($filepath, 'r');
        if (!$fh) {
            $this->setCache(false);
            return false;
        }
        $data = false;
        if (flock($fh, LOCK_SH)) {
            $data = trim(stream_get_contents($fh));
        }
        fclose($fh);
        $this->setCache($data);
        return $data;
    }

    /**
     * Set cache data
     * @param string $cache_data
     * @return void
     */
    private function setCache($cache_data)
    {
        $this->last_update_time_cache = time();
        $this->cache_data = $cache_data;
    }

    /**
     * Set state without checking
     * @param string $state
     * @return bool
     */
    private function setStateWithoutCheck($state)
    {
        $func = function($data) use ($state) {
            return $state;
        };
        $new_data = $this->editFileWithClosure($this->state_filepath, $func, false);
        $this->setCache($new_data);
        return (bool)$new_data;
    }

    /**
     * Get current status
     * @return string
     */
    private function getCurrentState()
    {
        $current_state = $this->cache_data;
        if (is_null($this->cache_data) || $this->last_update_time_cache + $this->cache_ttl < time()) {
            $current_state = $this->readFile($this->state_filepath);
        }
        if (in_array($current_state, [self::STATE_WORKING, self::STATE_DONE, self::STATE_CANCELED])) {
            return $current_state;
        }
        return self::STATE_NEW;
    }

}
/**
 * Class MDSBackup Backup data to csv
 */
class MDSBackup
{
    private $fhandle;
    private $hmemory;
    private $uniq = [];

    /**
     * MDSBackup constructor.
     * @param string $file
     */
    public function __construct($file = '')
    {
        if ($file == '') {
            $file = getcwd();
            $file .= '/mds_backup_' . time() . '.csv';
        }
        $this->fhandle = fopen($file, 'a');
        $this->hmemory = fopen('php://memory', 'w+');

        if (!($this->fhandle && $this->hmemory)) {
            throw new MDSException(MDSErrors::MDS_BACKUP_ERROR);
        }
    }

    /**
     * Backup one record to csv
     * @param $db
     * @param $table
     * @param $field
     * @param $id
     * @param $data
     */
    public function backup($db, $table, $field, $key, $id, $data)
    {
        if (isset($this->uniq[$db][$table][$field][$key][$id])) {
            return;
        }
        fputcsv($this->hmemory, [$db, $table, $field, $key, $id, base64_encode($data)]);
        $size = fstat($this->hmemory);
        $size = $size['size'];
        if ($size > 32768) {
            $this->flush();
        }
        $this->uniq[$db][$table][$field][$key][$id] = '';
    }

    /**
     * Backup array of records to csv
     * @param $rows
     */
    public function backupBatch($rows)
    {
        foreach($rows as list($db, $table, $field, $key, $id, $data)) {
             $this->backup($db, $table, $field, $key, $id, $data);
        }
    }

    /**
     * Flush to disk and close handles
     */
    public function finish()
    {
        $this->uniq = [];
        $this->flush();
        fclose($this->hmemory);
        fclose($this->fhandle);
    }

    /**
     * Flush to disk
     */
    private function flush()
    {
        rewind($this->hmemory);
        stream_copy_to_stream($this->hmemory, $this->fhandle);
        fflush($this->fhandle);
        rewind($this->hmemory);
        ftruncate($this->hmemory, 0);
    }
}
class MDSCleanup
{
    public static function clean($entry, $clean_db, $connection, $query, $field, $key, $report = null, $table_config = null)
    {
        $old_content = $entry->getContent();
        $c = $entry->getB64decodedContent() ?? $entry->getContent();
        $clean_result = CleanUnit::CleanContent($c, $clean_db, true, $table_config['escaped'] ?? false);
        if ($clean_result) {
            if ($entry->getB64decodedContent() !== null) {
                $c = base64_encode($c);
            }
            $query_str = 'UPDATE `' . $query->getDb() . '`.`' . $query->getTable() . '` SET `' . $field . '`=\'' . $connection->real_escape_string($c) . '\'';
            $query_str .= ' WHERE `' . $query->getKey() . '`=' . $key . ' AND `' . $field . '`=\'' . $connection->real_escape_string($old_content) . '\';';
            if ($connection->query($query_str) && $connection->affected_rows === 1 && $old_content !== $c) {
                return $clean_result;
            }
        }
        return false;
    }

    public static function cleanBatch($list, $detected, &$cleaned, $clean_db, $connection, $query, $progress = null, $table_config = null)
    {
        if ($list->isEntriesForclean()) {
            @$connection->begin_transaction(MYSQLI_TRANS_START_READ_WRITE);
            foreach ($list->getEntriesForClean() as $index => $entry) {
                $clean = self::clean($entry, $clean_db, $connection, $query, $entry->getField(), $entry->getKey(), null, $table_config);
                $list->addCleanResult($index, $clean);
                if ($clean) {
                    $cleaned++;
                }
                if ($progress instanceof MDSProgress) {
                    $progress->updateProgress($entry->getKey(), $detected, $cleaned, $query->getDB(), $query->getTable());
                }
            }
            @$connection->commit();
        }
    }
}

/**
 * Class MDSRestore Restore data from csv backup
 */
class MDSRestore
{
    private $fhandle;
    private $connection;
    private $progress;
    private $report;
    private $current_row = 0;
    private $start_time = 0;
    private $state = null;
    private $log = null;

    /**
     * MDSRestore constructor.
     * @param string        $file
     * @param mysqli        $connection
     * @param MDSProgress   $progress
     * @param MDSJSONReport $report
     * @param MDSState      $state
     */
    public function __construct($file, $connection, $progress = null, $report = null, MDSState $state = null, $log = null)
    {
        if (!$this->fhandle = fopen($file, 'r')) {
            throw new MDSException(MDSErrors::MDS_RESTORE_BACKUP_ERROR, $file);
        }
        $this->connection = $connection;
        $this->progress = $progress;
        $this->report = $report;
        $this->state = $state;
        $this->log = $log;

        $file = new \SplFileObject($file, 'r');
        $file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
        $file->seek(PHP_INT_MAX);

        if ($progress instanceof MDSProgress) {
            $progress->setTotal($file->key());
            $progress->setKeysRange(0, $file->key());
            $progress->setTotalTable($file->key());
            $progress->setCurrentTable(0, '');
        }

        $this->start_time = microtime(true);
    }

    /**
     * Write to db one record
     * @param $db
     * @param $table
     * @param $field
     * @param $key
     * @param $id
     * @param $data
     * @return bool
     */
    public function writeToDb($db, $table, $field, $key, $id, $data)
    {
        $ret = false;
        $data = base64_decode($data);
        $query_str = 'UPDATE `' . $db . '`.`' . $table . '` SET `' . $field . '`=\'' . $this->connection->real_escape_string($data) . '\'';
        $query_str .= ' WHERE `' . $key . '`=' . $id .';';
        if ($this->connection->query($query_str) && $this->connection->affected_rows === 1) {
            $ret = true;
        }
        if ($this->progress instanceof MDSProgress) {
            $this->progress->updateProgress(++$this->current_row, 0, 0, $db, $table);
        }
        if (isset($this->report)) {
            if ($ret === true) {
                $this->report->addRestored($table, $id, $field);
            } else {
                $this->report->addRestoredError(MDSErrors::MDS_RESTORE_UPDATE_ERROR, $table, $id, $field);
            }

        }
        return $ret;
    }

    /**
     * Write to db array of records
     * @param $rows
     */
    public function writeToDbBatch($rows)
    {
        foreach($rows as list($db, $table, $field, $key, $id, $data)) {
            $this->writeToDb($db, $table, $field, $key, $id, $data);
        }
    }

    public function restore($count)
    {
        $batch = $count;
        $for_restore = [];
        while (true) {
            if ($this->isCanceled()) {
                $this->log->info('Task canceled in progress');
                $this->report->setState(MDSJSONReport::STATE_CANCELED);
                break;
            }
            $row = fgetcsv($this->fhandle);
            if ($batch-- && $row) {
                $for_restore[] = $row;
                continue;
            } else {
                if (!$row && empty($for_restore)) {
                    break;
                }
            }
            if ($row) {
                $for_restore[] = $row;
            }
            $this->writeToDbBatch($for_restore);
            $for_restore = [];
            $batch = $count;
        }
    }

    /**
     * Close file handle and save report
     */
    public function finish()
    {
        fclose($this->fhandle);
        if (isset($this->report)) {
            $this->report->setCountTablesScanned(1);
            $this->report->setRunningTime(microtime(true) - $this->start_time);
        }
    }

    /**
     * Check on cancel
     * @return bool
     */
    private function isCanceled()
    {
        if (is_null($this->state)) {
            return false;
        }
        return $this->state->isCanceled();
    }

}

/**
 * Class MDSUrls store urls data
 */
class MDSUrls
{
    private $optimized_db;
    private $urls;

    /**
     * MDSUrls constructor.
     * @param $file
     * @throws Exception
     */
    public function __construct($file)
    {
        if (empty($file) || !file_exists($file)) {
            throw new MDSException(MDSErrors::MDS_DB_URLS_ERROR, $file);
        }

        $db = new \SplFileObject($file, 'r');
        $db->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
        foreach ($db as $url) {
            $url = explode('-', $url, 2);
            $this->urls[$url[0]] = strpos($url[1],'//') === 0 ? substr_replace($url[1],'//(www\.)?',0,2) : $url[1];
        }
        unset($db);

        $this->optimized_db = $this->urls;
        $this->optSig($this->optimized_db);
    }

    /**
     * Signature optimization (glue)
     * @param $sigs
     */
    private function optSig(&$sigs)
    {
        $sigs = array_unique($sigs);

        // Add SigId
        foreach ($sigs as $index => &$s) {
            $s .= '(?<X' . $index . '>)';
        }
        unset($s);

        $fix = [
            '([^\?\s])\({0,1}\.[\+\*]\){0,1}\2[a-z]*e'  => '(?J)\.[+*](?<=(?<d>[^\?\s])\(..|(?<d>[^\?\s])..)\)?\g{d}[a-z]*e',
            'http://.+?/.+?\.php\?a'                    => 'http://[^?\s]++(?<=\.php)\?a',
            '\s*[\'"]{0,1}.+?[\'"]{0,1}\s*'             => '.+?',
            '[\'"]{0,1}.+?[\'"]{0,1}'                   => '.+?'
        ];

        $sigs = str_replace(array_keys($fix), array_values($fix), $sigs);
        
        $fix = [
            '~^\\\\[d]\+&@~'                            => '&@(?<=\d..)',
            '~^((\[\'"\]|\\\\s|@)(\{0,1\}\.?|[?*]))+~'  => ''
        ];

        $sigs = preg_replace(array_keys($fix), array_values($fix), $sigs);

        $this->optSigCheck($sigs);

        $tmp = [];
        foreach ($sigs as $i => $s) {
            if (!preg_match('~^(?>(?!\.[*+]|\\\\\d)(?:\\\\.|\[.+?\]|.))+$~', $s)) {
                unset($sigs[$i]);
                $tmp[] = $s;
            }
        }
        
        usort($sigs, 'strcasecmp');
        $txt = implode("\n", $sigs);

        for ($i = 24; $i >= 1; ($i > 4) ? $i -= 4 : --$i) {
            $txt = preg_replace_callback('#^((?>(?:\\\\.|\\[.+?\\]|[^(\n]|\((?:\\\\.|[^)(\n])++\))(?:[*?+]\+?|\{\d+(?:,\d*)?\}[+?]?|)){' . $i . ',})[^\n]*+(?:\\n\\1(?![{?*+]).+)+#im', [$this, 'optMergePrefixes'], $txt);
        }

        $sigs = array_merge(explode("\n", $txt), $tmp);
        
        $this->optSigCheck($sigs);
    }

    /**
     * @param $m
     * @return string
     */
    private function optMergePrefixes($m)
    {
        $limit = 8000;

        $prefix     = $m[1];
        $prefix_len = strlen($prefix);

        $len = $prefix_len;
        $r   = [];

        $suffixes = [];
        foreach (explode("\n", $m[0]) as $line) {

            if (strlen($line) > $limit) {
                $r[] = $line;
                continue;
            }

            $s = substr($line, $prefix_len);
            $len += strlen($s);
            if ($len > $limit) {
                if (count($suffixes) == 1) {
                    $r[] = $prefix . $suffixes[0];
                } else {
                    $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
                }
                $suffixes = [];
                $len      = $prefix_len + strlen($s);
            }
            $suffixes[] = $s;
        }

        if (!empty($suffixes)) {
            if (count($suffixes) == 1) {
                $r[] = $prefix . $suffixes[0];
            } else {
                $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
            }
        }

        return implode("\n", $r);
    }

    /*
     * Checking errors in pattern
     */
    private function optSigCheck(&$sigs)
    {
        $result = true;

        foreach ($sigs as $k => $sig) {
            if (trim($sig) == "") {
                unset($sigs[$k]);
                $result = false;
            }

            if (@preg_match('~' . $sig . '~smiS', '') === false) {
                $error = error_get_last();
                unset($sigs[$k]);
                $result = false;
            }
        }

        return $result;
    }

    /**
     * Return optimized db
     * @return mixed
     */
    public function getDb()
    {
        return $this->optimized_db;
    }

    public function getSig($l_Found)
    {
        foreach ($l_Found as $key => &$v) {
            if (is_string($key) && $v[1] !== -1 && strlen($key) > 1) {
                return 'CMW-URL-' . substr($key, 1);
            }
        }
        return null;
    }

    public function getSigUrl($id)
    {
        if (strpos($id, 'CMW-URL-') !== false) {
            $id = (int)str_replace('CMW-URL-', '', $id);
        }
        return $this->urls[$id];
    }

}
class MDSErrors
{
    const MDS_CONNECT_ERROR             = 1;
    const MDS_BACKUP_ERROR              = 2;
    const MDS_PROGRESS_FILE_ERROR       = 3;
    const MDS_PROGRESS_SHMEM_ERROR      = 4;
    const MDS_PROGRESS_SHMEM_CRT_ERROR  = 5;
    const MDS_RESTORE_BACKUP_ERROR      = 6;
    const MDS_NO_SUP_TABLES_ERROR       = 7;
    const MDS_CONFIG_ERROR              = 8;
    const MDS_DB_URLS_ERROR             = 9;
    const MDS_NO_DATABASE               = 10;
    const MDS_PRESCAN_CONFIG_ERROR      = 11;
    const MDS_REPORT_ERROR              = 12;

    const MDS_DROP_CONNECT_ERROR        = 13;

    const MDS_AVD_DB_NOTFOUND           = 14;
    const MDS_AVD_DB_INVALID            = 15;
    const MDS_INVALID_CMS_CONFIG        = 16;
    const MDS_CMS_CONFIG_NOTSUP         = 17;
    const MDS_MULTIPLE_DBS              = 18;
    const MDS_NO_SCANNED                = 19;

    const MDS_CLEANUP_ERROR             = 101;
    const MDS_RESTORE_UPDATE_ERROR      = 102;

    const MESSAGES = [
        self::MDS_CONNECT_ERROR               => 'Can\'t connect to database: %s',
        self::MDS_BACKUP_ERROR                => 'Can\'t create backup file in %s',
        self::MDS_PROGRESS_FILE_ERROR         => 'Can\'t create progress file in %s',
        self::MDS_PROGRESS_SHMEM_ERROR        => 'Can\'t use progress shared memory with key %s',
        self::MDS_PROGRESS_SHMEM_CRT_ERROR    => 'Can\'t create progress shared memory with key %s',
        self::MDS_RESTORE_BACKUP_ERROR        => 'Can\'t open backup file for restore in %s',
        self::MDS_NO_SUP_TABLES_ERROR         => 'Not found any supported tables in db %s in %s@%s',
        self::MDS_CONFIG_ERROR                => 'Can\'t open configuration file in %s',
        self::MDS_DB_URLS_ERROR               => 'Can\'t open urls db file %s',
        self::MDS_DROP_CONNECT_ERROR          => 'Lost connection to database: %s',
        self::MDS_NO_DATABASE                 => 'No database selected. Please, provide database name.',
        self::MDS_PRESCAN_CONFIG_ERROR        => 'Can\'t load prescan config from %s',
        self::MDS_REPORT_ERROR                => 'Can\'t write report to %s',
        self::MDS_CLEANUP_ERROR               => 'Error in cleanup during update table record.',
        self::MDS_RESTORE_UPDATE_ERROR        => 'Error in restore during update table record.',
        self::MDS_AVD_DB_NOTFOUND             => 'Failed loading DB from "%s": DB file not found.',
        self::MDS_AVD_DB_INVALID              => 'Failed loading DB from "%s": invalid DB format.',
        self::MDS_INVALID_CMS_CONFIG          => 'Failed loading CMS config %s',
        self::MDS_CMS_CONFIG_NOTSUP           => 'Can\'t parse config for CMS: %s',
        self::MDS_MULTIPLE_DBS                => 'For multiple DBs we support only scan, please select one db for work.',
        self::MDS_NO_SCANNED                  => 'No database to process.',
    ];

    public static function getErrorMessage($errcode, ...$args) {
        return vsprintf(self::MESSAGES[$errcode] ?? '', ...$args);
    }

}
class MDSException extends Exception
{
    private $_errcode = 0;
    private $_errmsg = '';

    public function __construct($errcode, ...$args)
    {
        $this->_errcode = $errcode;
        $this->_errmsg = MDSErrors::getErrorMessage($errcode, $args);
        parent::__construct($this->_errmsg);
    }

    public function getErrCode()
    {
        return $this->_errcode;
    }

    public function getErrMsg()
    {
        return $this->_errmsg;
    }
}
class MDSDBCredsFromConfig
{
    private $finder;
    private $creds = [];

    public function __construct($finder, $path)
    {
        $res = [];
        $this->finder = $finder;
        foreach ($this->finder->find($path) as $file_config) {
            $config = @file_get_contents($file_config, false, null, 0, 50000);
            if (preg_match('~define\(\s*[\'"]DB_NAME[\'"]\s*,\s*(?|\'([^\']+)\'|"([^"]+)")~msi', $config,$matches)) {
                $res['db_name'] = $matches[1];
            }
            if (preg_match('~define\(\s*[\'"]DB_USER[\'"]\s*,\s*(?|\'([^\']+)\'|"([^"]+)")~msi', $config,$matches)) {
                $res['db_user'] = $matches[1];
            }
            if (preg_match('~define\(\s*[\'"]DB_PASSWORD[\'"]\s*,\s*(?|\'([^\']+)\'|"([^"]+)")~msi', $config,$matches)) {
                $res['db_pass'] = $matches[1];
            }
            if (preg_match('~define\(\s*[\'"]DB_HOST[\'"]\s*,\s*(?|\'([^\']+)\'|"([^"]+)")~msi', $config,$matches)) {
                $host = explode(':', $matches[1]);
                $res['db_host'] = $host[0];
                $res['db_port'] = isset($host[1]) ? (int)$host[1] : 3306;
            }
            if (preg_match('~table_prefix\s*=\s*(?|\'([^\']+)\'|"([^"]+)");~msi', $config,$matches)) {
                $res['db_prefix'] = $matches[1];
            }

            if (isset($res['db_name']) && isset($res['db_user']) && isset($res['db_pass'])
                && isset($res['db_host']) && isset($res['db_port']) && isset($res['db_prefix'])
            ) {
                $this->creds[] = $res;
            }
        }
        $this->creds = array_unique($this->creds, SORT_REGULAR);
    }

    public function getCreds()
    {
        return $this->creds;
    }

    public function printCreds()
    {
        echo 'Found following db credentials: ' . PHP_EOL;
        foreach ($this->creds as $db_cred) {
            echo '--------------------------------------------------------' . PHP_EOL;
            echo 'Host:   ' . $db_cred['db_host']   . PHP_EOL;
            echo 'Port:   ' . $db_cred['db_port']   . PHP_EOL;
            echo 'User:   ' . $db_cred['db_user']   . PHP_EOL;
            echo 'Pass:   ' . $db_cred['db_pass']   . PHP_EOL;
            echo 'Name:   ' . $db_cred['db_name']   . PHP_EOL;
            echo 'Prefix: ' . $db_cred['db_prefix'] . PHP_EOL;
        }
    }

    public function printForXArgs()
    {
        foreach ($this->creds as $db_cred) {
            echo  $db_cred['db_host'] . ';;' . $db_cred['db_port'] . ';;' . $db_cred['db_user'] . ';;' . $db_cred['db_pass'] . ';;' . $db_cred['db_name'] . ';;' . $db_cred['db_prefix'] . PHP_EOL;
        }
    }

}
class MDSCMSConfigFilter
{
    private $followSymlink = true;

    public function __construct()
    {

    }

    private function fileExistsAndNotNull($path)
    {
        return (is_file($path) && file_exists($path) && (filesize($path) > 2048));
    }

    public function needToScan($file, $stat = false, $only_dir = false)
    {
        if (is_dir($file)) {
            return true;
        }
        if ($this->fileExistsAndNotNull($file) && basename($file) === 'wp-config.php') {
            return true;
        }
        return false;
    }

    public function isFollowSymlink()
    {
        return $this->followSymlink;
    }

}

class MDSCHRequest
{

    const API_URL = 'https://api.imunify360.com/api/send-message';
    const DEBUG_API_URL = 'http://127.0.0.1:8888';

    private $timeout = 10;
    private $debug = false;

    /**
     * MDSCHRequest constructor.
     * @param int $timeout
     */
    public function __construct($timeout = 10, $debug = false)
    {
        $this->timeout = $timeout;
        $this->debug = $debug;
    }

    /**
     * @param $data
     * @return bool|array
     */
    public function request($data)
    {
        $result = '';
        $json_data = json_encode($data);

        try {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $this->getApiUrl());
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
            curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $this->timeout);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $json_data);
            $result = curl_exec($ch);
            curl_close($ch);
        } catch (Exception $e) {
            fwrite(STDERR, 'Warning: [MDS] Curl: ' . $e->getMessage() . PHP_EOL);
            return false;
        }
        return @json_decode($result, true);
    }

    private function getApiUrl()
    {
        return $this->debug ? self::DEBUG_API_URL : self::API_URL;
    }
}
class MDSSendToCH
{
    private $request = null;
    private $report = null;
    private $lic = null;

    public function __construct($request, $lic)
    {
        $this->request = $request;
        $this->lic = $lic;
    }

    public function prepareData($report)
    {
        $this->report = $report;
        $this->array_walk_recursive_delete($this->report, function($value, $key, $userdata) {
            if ($key === 'row_ids' || $key === 'rows_with_error') {
                return true;
            }
            return false;
        });
        $this->report = ['items' => [$this->report]];
    }

    public function send()
    {
        $license = $this->lic->getLicData();
        $data = [
            'method' => 'MDS_SCAN_LIST',
            'license' => $license,
            'payload' => $this->report,
            'server_id' => $license['id'],
        ];
        $res = $this->request->request($data);
        if ($res['status'] === 'ok') {
            return true;
        } else {
            fwrite(STDERR, 'Warning: [MDS] Invalid response: ' . json_encode($res) . PHP_EOL);
            return false;
        }
    }

    /**
     * Remove any elements where the callback returns true
     *
     * @param  array    $array    the array to walk
     * @param  callable $callback callback takes ($value, $key, $userdata)
     * @param  mixed    $userdata additional data passed to the callback.
     * @return array
     */
    private function array_walk_recursive_delete(array &$array, callable $callback, $userdata = null)
    {
        foreach ($array as $key => &$value) {
            if (is_array($value)) {
                $value = $this->array_walk_recursive_delete($value, $callback, $userdata);
            }
            if ($callback($value, $key, $userdata)) {
                unset($array[$key]);
            }
        }
        return $array;
    }
}

class MDSDetachedMode
{
    protected $workdir;
    protected $scan_id;
    protected $pid_file;
    protected $done_file;
    protected $sock_file;
    protected $complete = [
        'scan' => 'MALWARE_SCAN_COMPLETE',
        'clean' => 'MALWARE_CLEAN_COMPLETE',
        'restore' => 'MALWARE_RESTORE_COMPLETE'
    ];

    protected $op = null;

    public function __construct($scan_id, $op, $basedir = '/var/imunify360/dbscan/run', $sock_file = '/var/run/defence360agent/generic_sensor.sock.2')
    {
        $basedir = $basedir . DIRECTORY_SEPARATOR . $op;
        $this->scan_id  = $scan_id;
        $this->setWorkDir($basedir, $scan_id);
        $this->pid_file     = $this->workdir . '/pid';
        $this->done_file    = $this->workdir . '/done';
        $this->setSocketFile($sock_file);
        $this->savePid();
        $this->checkWorkDir($this->workdir);
    }

    public function getWorkDir()
    {
        return $this->workdir;
    }

    protected function checkWorkDir($workdir)
    {
        if (!file_exists($workdir) && !mkdir($workdir) && !is_dir($workdir)) {
            die('Error! Cannot create workdir ' . $workdir . ' for detached scan.');
        } elseif (file_exists($workdir) && !is_writable($workdir)) {
            die('Error! Workdir ' . $workdir . ' is not writable.');
        } 
    }

    protected function savePid()
    {
        file_put_contents($this->pid_file, strval(getmypid()));
    }

    public function complete()
    {
        @touch($this->done_file);
        $complete = [
            'method'        => 'MALWARE_SCAN_COMPLETE',
            'scan_id'       => $this->scan_id,
            'resource_type' => 'db',
        ];
        if ($this->op && isset($this->complete[$this->op])) {
            $complete['method'] = $this->complete[$this->op];
        }
        $json_complete = json_encode($complete) . "\n";
        $socket = @fsockopen('unix://' . $this->sock_file);
        if (is_resource($socket)) {
            stream_set_blocking($socket, false);
            fwrite($socket, $json_complete);
            fclose($socket);
        }
    }

    public function setOp($op)
    {
        if ($op && isset($this->complete[$op])) {
            $this->op = $op;
        }
    }

    protected function setWorkDir($dir, $scan_id)
    {
        $this->workdir = $dir . '/' . $scan_id;
    }

    protected function setSocketFile($sock)
    {
        $this->sock_file = $sock;
    }
}

class MDSDBCredsFromAVD
{
    protected $dbh;

    protected $avd_path_prev    = '/var/imunify360/components_versions.sqlite3';
    protected $avd_path         = '/var/lib/cloudlinux-app-version-detector/components_versions.sqlite3';
    protected $found_apps       = 0;
    private $path_field         = 'real_path';

    public function __construct()
    {
        $path = file_exists($this->avd_path) ? $this->avd_path : (file_exists($this->avd_path_prev) ? $this->avd_path_prev : '');

        if ($path === '') {
            throw new MDSException(MDSErrors::MDS_AVD_DB_NOTFOUND, $this->avd_path);
        }

        $this->openAppDB($path);
        if (!$this->haveTable('apps')) {
            throw new MDSException(MDSErrors::MDS_AVD_DB_INVALID, $this->avd_path);
        }
        if (!$this->haveColumn('apps', $this->path_field)) {
            $this->path_field = 'path';
        }
    }

    public function getCredsFromApps($paths, $apps = null, $glob = false)
    {
        foreach($this->getApps($paths, $apps, $glob) as $row) {
            try {
                $config = MDSCMSAddonFactory::getCMSConfigInstance($row['title'], $row[$this->path_field]);
                $res = $config->parseConfig();
                $res['app_owner_uid'] = $row['app_uid'] ?? null;
                yield $res;
            } catch (MDSException $ex) {
                $res['error'] = $ex;
                yield $res;
            }
        }
        $this->dbh = null;
    }

    public function getAppsCount()
    {
        return $this->found_apps;
    }

    public function countApps($paths, $apps = null, $glob = false)
    {
        list($sql, $params) = $this->generateAppDBQuery($glob, $apps, $paths);
        $count_sql = 'SELECT COUNT(*) as count FROM (' . $sql . ');';
        $result = $this->execQueryToAppDB($count_sql, $params);
        $this->found_apps = (int)$result->fetchArray(SQLITE3_NUM)[0];
    }

    ////////////////////////////////////////////////////////////////////////////

    private function getApps($paths, $apps, $glob)
    {
        list($sql, $params) = $this->generateAppDBQuery($glob, $apps, $paths);
        $res = $this->execQueryToAppDB($sql, $params);
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            yield $row;
        }
    }

    private function openAppDB($db)
    {
        $this->dbh = new \SQLite3($db);
    }

    private function haveColumn($table_name, $column_name)
    {
        $sql    = 'PRAGMA table_info("' . $table_name . '")';
        $stmt   = $this->dbh->prepare($sql);
        $result = $stmt->execute();
        while ($row = $result->fetchArray(SQLITE3_ASSOC))
        {
            if ($row['name'] == $column_name) {
                return true;
            }
        }
        return false;
    }

    private function haveTable($table_name)
    {
        $sql = 'PRAGMA table_info("' . $table_name . '")';
        $stmt   = $this->dbh->prepare($sql);
        $result = $stmt->execute();
        return (bool)$result->fetchArray();
    }

    /**
     * @param string $query
     * @param array  $params
     *
     * @return SQLite3Result
     */
    private function execQueryToAppDB(string $query, array $params)
    {
        $stmt  = $this->dbh->prepare($query);
        foreach ($params as $param_name => $param_value)
        {
            $stmt->bindValue($param_name, $param_value);
        }
        return $stmt->execute();
    }

    /**
     * @param $glob
     * @param $apps
     * @param $paths
     *
     * @return array
     */
    private function generateAppDBQuery($glob, $apps, $paths): array
    {
        $params = [];

        $sql = 'SELECT *'
            . ' FROM apps'
            . ' WHERE (';
        for ($i = 0, $iMax = count($paths); $i < $iMax; $i++) {
            $sql .= $this->path_field . ' ';
            $sql .= $glob ? 'GLOB ' : '= ';
            $sql .= ':path' . $i;
            $params[':path' . $i] = $paths[$i];
            if ($i !== $iMax - 1) {
                $sql .= ' OR ';
            }
        }

        $sql .= ')';

        $sql .= isset($apps) ? ' AND title IN (' : '';
        for ($i = 0, $iMax = count($apps); $i < $iMax; $i++) {
            $sql .= ':app' . $i;
            $params[':app' . $i] = $apps[$i];
            if ($i !== $iMax - 1) {
                $sql .= ', ';
            }
        }
        $sql .= isset($apps) ? ')' : '';
        $sql .= ' GROUP BY ' . $this->path_field . ', title';

        return [$sql, $params];
    }

}


class MDSCMSAddonFactory
{
    public static function getCMSConfigInstance($app, $path)
    {
        $class = 'MDS' . ucfirst(str_replace('_', '', $app)) . 'Config';

        if (!class_exists($class)) {
            throw new MDSException(MDSErrors::MDS_CMS_CONFIG_NOTSUP, $app);
        }
        return new $class($path);
    }
}

class MDSCMSAddon
{
    const CONFIG_FILE = '';
    const MIN_SIZE = '1000';

    protected $app;
    protected $path;

    public function __construct($path)
    {
        if (!file_exists($path . '/' . static::CONFIG_FILE)
            || !is_readable($path . '/' . static::CONFIG_FILE)
            || (filesize($path . '/' . static::CONFIG_FILE) < static::MIN_SIZE)
        ) {
            throw new MDSException(MDSErrors::MDS_INVALID_CMS_CONFIG, $path . '/' . static::CONFIG_FILE);
        }

        $this->path = $path;
    }

    public function parseConfig()
    {

    }

}
class MDSAVDPathFilter
{
    private $ignoreList = [];

    public function __construct($filepath)
    {
        if (!file_exists($filepath) || !is_file($filepath) || !is_readable($filepath)) {
            return;
        }

        $content = file_get_contents($filepath);
        $list = explode("\n", $content);
        foreach ($list as $base64_filepath) {
            if ($base64_filepath !== '') {
                $this->ignoreList[$base64_filepath] = '';
            }
        }
    }

    public function needToScan($file)
    {
        $tree = $this->getTree($file);
        if ($this->pathRelatesTo($tree, $this->ignoreList, true)) {
            return false;
        }
        return true;
    }

    private function getTree($file)
    {
        $tree = [];
        $path = $file;
        while ($path !== '.' && $path !== '/') {
            $path = dirname($path, 1);
            $tree[] = $path;
        }
        $tree[] = $file;
        return $tree;
    }

    private function pathRelatesTo($tree, $pathes, $base64 = false)
    {
        foreach ($tree as $path) {
            if ($base64) {
                $path = base64_encode($path);
            }
            if (isset($pathes[$path])) {
                return true;
            }
        }
        return false;
    }
}

class MDSCollectUrlsRequest
{

    const API_URL = 'https://api.imunify360.com/api/mds/check-urls';
    const DEBUG_API_URL = 'http://127.0.0.1:8888';

    private $timeout = 10;
    private $debug = false;

    /**
     * MDSCollectUrlsRequest constructor.
     * @param int $timeout
     */
    public function __construct($timeout = 10, $debug = false)
    {
        $this->timeout = $timeout;
        $this->debug = $debug;
    }

    /**
     * @param $data
     * @return bool|array
     */
    public function request($data)
    {
        $result = '';
        $json_data = json_encode($data);

        try {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $this->getApiUrl());
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
            curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $this->timeout);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $json_data);
            $result = curl_exec($ch);
            curl_close($ch);
        } catch (Exception $e) {
            fwrite(STDERR, 'Warning: [MDS] Curl: ' . $e->getMessage() . PHP_EOL);
            return false;
        }
        return @json_decode($result, true);
    }

    private function getApiUrl()
    {
        return $this->debug ? self::DEBUG_API_URL : self::API_URL;
    }
}
class MDSSendUrls
{
    private $request = null;

    public function __construct($request)
    {
        $this->request = $request;
    }

    public function send($urls)
    {
        $data = [
            'urls'      => $urls,
            'source'    => 'MDS',
        ];
        $res = $this->request->request($data);
        if ($res['status'] === 'ok') {
            return true;
        } else {
            fwrite(STDERR, 'Warning: [MDS] Invalid response: ' . json_encode($res) . PHP_EOL);
            return false;
        }
    }
}

class MDSWpcoreConfig extends MDSCMSAddon
{
    const CONFIG_FILE = 'wp-config.php';

    public function parseConfig()
    {
        $res = [];
        $config = @file_get_contents($this->path . '/' . self::CONFIG_FILE, false, null, 0, 50000);
        if (preg_match('~define\(\s*[\'"]DB_NAME[\'"]\s*,\s*(?|\'([^\']+)\'|"([^"]+)")~msi', $config,$matches)) {
            $res['db_name'] = $matches[1];
        }
        if (preg_match('~define\(\s*[\'"]DB_USER[\'"]\s*,\s*(?|\'([^\']+)\'|"([^"]+)")~msi', $config,$matches)) {
            $res['db_user'] = $matches[1];
        }
        if (preg_match('~define\(\s*[\'"]DB_PASSWORD[\'"]\s*,\s*(?|\'([^\']+)\'|"([^"]+)")~msi', $config,$matches)) {
            $res['db_pass'] = $matches[1];
        }
        if (preg_match('~table_prefix\s*=\s*(?|\'([^\']+)\'|"([^"]+)");~msi', $config,$matches)) {
            $res['db_prefix'] = $matches[1];
        }
        if (preg_match('~define\(\s*[\'"]DB_HOST[\'"]\s*,\s*(?|\'([^\']+)\'|"([^"]+)")~msi', $config,$matches)) {
            $host = explode(':', $matches[1]);
            $res['db_host'] = $host[0];
            $res['db_port'] = isset($host[1]) ? (int)$host[1] : 3306;
        }

        if (isset($res['db_name']) && isset($res['db_user']) && isset($res['db_pass']) && isset($res['db_host'])
            && isset($res['db_port']) && isset($res['db_prefix'])
        ) {
            $res['db_app'] = 'wp_core';
            $res['db_path'] = $this->path;
            return $res;
        } else {
            return false;
        }
    }
}
/**
 * Class stored all entries for scan/clean and scan/clean results
 */
class MDSProcessingList
{
    /**
     * Array of indexes of $entries array that will be scanned
     * @var int[]
     */
    private $forscan = [];

    /**
     * Array of indexes of $entries array that will be cleaned
     * @var int[]
     */
    private $forclean = [];

    /**
     * Array of entries that we get during prescan db query
     * @var MDSEntry[]
     */
    private $entries = [];

    /**
     * Scan results linked with $entries array
     * @var MDSMalwareEntry[]
     */
    private $scan_res = [];

    /**
     * Clean results linked with $entries array
     * @var array
     */
    private $clean_res = [];

    /**
     * Create new MDSEntry object from $data array and add to general list
     * @param array $data
     * @param MDSPreScanQuery $query
     */

    /**
     * Array of uniq infected keys
     * @var array
     */
    private $only_black_uniq = [];

    /**
     * Infected keys counter
     * @var int
     */
    private $count_black_uniq = 0;

    public function addToList(array $data, MDSPreScanQuery $query)
    {
        $key = $data['mds_key'];
        $fields = [];
        unset($data['mds_key'], $data['mds_field']);
        foreach ($data as $k => &$v) {
            $field = explode('_', $k);
            if (isset($field[1])) {
                if ($field[1] === 'b64' && $v === '1') {
                    $fields[$field[0]] = true;
                }
                unset($data[$k]);
            }
        }
        unset($v);
        foreach ($data as $k => $v) {
            $this->entries[] = new MDSEntry(
                $key,
                $query->getFieldByAlias($k),
                $k,
                $v,
                (isset($fields[$k]) && $fields[$k] === true)
            );
        }
    }

    /**
     * Clear list
     */
    public function clear()
    {
        $this->forscan = [];
        $this->forclean = [];
        $this->entries = [];
        $this->scan_res = [];
        $this->clean_res = [];
        $this->only_black_uniq = [];
    }

    /**
     * Send all entries to scan
     */
    public function markAllEntriesForScan()
    {
        $this->forscan = array_keys($this->entries);
    }

    /**
     * Get last db key value from $entries
     * @return int
     */
    public function getLastKey()
    {
        end($this->entries);
        $key = current($this->entries)->getKey();
        reset($this->entries);
        return $key;
    }

    /**
     * Add item for clean list
     * @param int $index
     */
    public function addForClean(int $index)
    {
        $this->forclean[] = $index;
    }

    /**
     * Get MDSEntry object with $index key
     * @param $index
     * @return MDSEntry
     */
    public function getEntry($index)
    {
        return $this->entries[$index];
    }

    /**
     * Get all MDSEntry objects, that marked to scan
     * @return Generator
     */
    public function getEntriesForScan()
    {
        foreach($this->forscan as $index) {
            yield $index => $this->entries[$index];
        }
    }

    /**
     * Get all MDSEntry objects, that was scanned and have scan report
     * @return Generator
     */
    public function getEntriesWithScanResults()
    {
        foreach($this->scan_res as $index => $result) {
            if ($result !== false) {
                yield $index => $this->entries[$index];
            }
        }
    }

    /**
     * Get all MDSEntry objects, that was scanned and have scan report, only malware
     * @return Generator
     */
    public function getEntriesWithScanResultsOnlyBlack()
    {
        foreach($this->scan_res as $index => $result) {
            if ($result !== false) {
                if (
                    $this->entries[$index]->getScan()->isBlackUrlDetected()
                    || $this->entries[$index]->getScan()->isMalwareDetected()
                ) {
                    yield $index => $this->entries[$index];
                }
            }
        }
    }

    /**
     * Get count of uniq keys that was scanned and have scan report, only malware
     * @return int
     */
    public function getCountKeysWithScanResultsOnlyBlack()
    {
        return $this->count_black_uniq;
    }

    /**
     * Get all MDSEntry objects, that was cleaned and have clean report
     * @return Generator
     */
    public function getEntriesWithCleanResults()
    {
        foreach($this->clean_res as $index => $result) {
            if ($result !== false) {
                yield $index => $this->entries[$index];
            }
        }
    }

    /**
     * Get all MDSEntry objects, that was cleaned with errors
     * @return Generator
     */
    public function getEntriesWithCleanErrors()
    {
        foreach($this->clean_res as $index => $result) {
            if ($result === false) {
                yield $index => $this->entries[$index];
            }
        }
    }

    /**
     * Add scan result to MDSEntry object
     * @param int $index
     * @param array|bool $result
     */
    public function addScanResult(int $index, $result)
    {
        $this->scan_res[$index] = $result ? new MDSMalwareEntry($result) : false;
        $this->entries[$index]->setScan($this->scan_res[$index]);
        if ($this->scan_res[$index] && ($this->scan_res[$index]->isMalwareDetected() || $this->scan_res[$index]->isBlackUrlDetected())) {
            if (isset($this->only_black_uniq[$this->entries[$index]->getKey()])) {
                return;
            }
            $this->only_black_uniq[$this->entries[$index]->getKey()] = '';
            $this->count_black_uniq++;
        }
    }

    /**
     * Add clean result to MDSEntry object
     * @param int $index
     * @param array|bool $result
     */
    public function addCleanResult(int $index, $result)
    {
        if ($result === false) {
            $this->clean_res[$index] = false;
        } else {
            foreach($result as $res) {
                $this->clean_res[$index][] = $res ? $res['id'] : false;
            }
        }
        $this->entries[$index]->setClean($this->clean_res[$index]);
    }

    /**
     * Get scan result for entry by index
     * @param int $index
     * @return MDSMalwareEntry
     */
    public function getScanResult(int $index)
    {
        return $this->scan_res[$index];
    }

    /**
     * Get clean result for entry by index
     * @param int $index
     * @return array
     */
    public function getCleanResult(int $index)
    {
        return $this->clean_res[$index];
    }

    /**
     * Do we have any entries for clean
     * @return bool
     */
    public function isEntriesForclean()
    {
        return !empty($this->forclean);
    }

    /**
     * count of all entries
     * @return int
     */
    public function getCount()
    {
        return count($this->entries);
    }

    /**
     * Do we have any entries in general list
     * @return bool
     */
    public function isEmpty()
    {
        return count($this->entries) === 0;
    }

    /**
     * Get all MDSEntry objects, that marked for clean
     * @return Generator
     */
    public function getEntriesForClean()
    {
        foreach($this->forclean as $index) {
            yield $index => $this->entries[$index];
        }
    }
}

/**
 * Class to store data of each entry that we want to scan/clean with references to scan/clean reports
 */
class MDSEntry
{
    /**
     * db field
     * @var string
     */
    private $field;

    /**
     * alias for field
     * @var string
     */
    private $alias;

    /**
     * content of row
     * @var string
     */
    private $content;

    /**
     * content of row base64 decoded if needed
     * @var string|null
     */
    private $b64decoded_content = null;

    /**
     * db key value
     * @var int
     */
    private $key;

    /**
     * reference to linked MDSMalwareEntry (ai-bolit report)
     * @var MDSMalwareEntry
     */
    private $scan_ref;

    /**
     * reference to clean result (array of signature names cleaned)
     * @var array
     */
    private $clean_ref;

    public function __construct(int $key, string $field, string $alias, string $content, bool $base64)
    {
        $this->key = $key;
        $this->alias = $alias;
        $this->field = $field;
        $this->content = $content;
        $this->b64decoded_content = $base64 ? base64_decode($content) : null;
    }

    /**
     * Get db field
     * @return string
     */
    public function getField()
    {
        return $this->field;
    }

    /**
     * Get db alias for field
     * @return string
     */
    public function getAlias()
    {
        return $this->alias;
    }

    /**
     * Get row content string
     * @return string
     */
    public function getContent()
    {
        return $this->content;
    }

    /**
     * Get base64 decoded content
     * @return string|null
     */
    public function getB64decodedContent()
    {
        return $this->b64decoded_content;
    }

    /**
     * Get db key value
     * @return int
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * link MDSMalwareEntry to this entry or false if nothing detected
     * @param bool|MDSMalwareEntry $scan
     */
    public function setScan(&$scan)
    {
        $this->scan_ref = $scan;
    }

    /**
     * link array of cleaned signature names to this entry or false if not cleaned
     * @param bool|array &$clean
     */
    public function setClean(&$clean)
    {
        $this->clean_ref = $clean;
    }

    /**
     * get linked MDSMalwareEntry object (scan report)
     * @return bool|MDSMalwareEntry
     */
    public function getScan()
    {
        return $this->scan_ref;
    }

    /**
     * get linked array of cleaned signatures
     * @return bool|array
     */
    public function getClean()
    {
        return $this->clean_ref;
    }
}

/**
 * Class to store data of each entry that was scanned and detected something (store ai-bolit report)
 */
class MDSMalwareEntry
{
    /**
     * Detected malware
     * @var MDSMalwareResult
     */
    private $malware = [];

    /**
     * Detected urls
     * @var MDSUrlResult[]
     */
    private $urls = [];

    /**
     * Unknown urls counter
     * @var int
     */
    private $unk_detected = 0;

    /**
     * Black urls counter
     * @var int
     */
    private $black_detected = 0;

    /**
     * Parse ai-bolit report and save data to object
     * @param $data
     */
    public function __construct(array $data)
    {
        if (isset($data['mlw'])) {
            $this->malware = new MDSMalwareResult($data['mlw']);
        }
        if (isset($data['url'])) {
            foreach ($data['url'] as $type => $urls) {
                $type = $type === 'unk' ? 'unknown' : $type;
                foreach ($urls as $url) {
                    if ($type === 'black') {
                        $this->black_detected++;
                    } else {
                        $this->unk_detected++;
                    }
                    $url[$type] = true;
                    $this->urls[] = new MDSUrlResult($url);
                }
            }
        }
    }

    /**
     * Is any malware entry in report
     * @return bool
     */
    public function isMalwareDetected()
    {
        return (isset($this->malware) && !empty($this->malware));
    }

    /**
     * Is any black url entry in report
     * @return bool
     */
    public function isBlackUrlDetected()
    {
        return $this->black_detected > 0;
    }

    /**
     * Is any unknown url entry in report
     * @return bool
     */
    public function isUnknownUrlDetected()
    {
        return $this->unk_detected > 0;
    }

    /**
     * Black url counter
     * @return int
     */
    public function countBlackUrlDetected()
    {
        return $this->black_detected;
    }

    /**
     * Unknown url counter
     * @return int
     */
    public function countUnknownUrlDetected()
    {
        return $this->unk_detected;
    }

    /**
     * Get snippet of malware detected or black url detected
     * @return string
     */
    public function getSnippet()
    {
        if ($this->isMalwareDetected()) {
            return $this->malware->getSnippet();
        } else if ($this->isBlackUrlDetected()) {
            foreach($this->getBlackUrls() as $url) {
                return $url->getSnippet();
            }
        }
    }

    /**
     * Get linked MDSMalwareResult object
     * @return MDSMalwareResult
     */
    public function getMalwareRes()
    {
        return $this->malware;
    }

    /**
     * Get Unknown urls list
     * @return Generator
     */
    public function getUnknownUrls()
    {
        foreach ($this->urls as $url) {
            if ($url->isUnknown()) {
                yield $url;
            }
        }
    }

    /**
     * Get black urls list
     * @return Generator
     */
    public function getBlackUrls()
    {
        foreach ($this->urls as $url) {
            if ($url->isBlack()) {
                yield $url;
            }
        }
    }
}

/**
 * Class to store data of detected malware
 */
class MDSMalwareResult
{
    /**
     * snippet
     * @var string
     */
    private $snippet;

    /**
     * signature id
     * @var string
     */
    private $sigid;

    /**
     * position
     * @var int
     */
    private $pos;

    /**
     * signature name
     * @var string
     */
    private $signame;

    public function __construct(array $data)
    {
        $this->snippet  = $data['content']  ?? '';
        $this->pos      = $data['pos']      ?? 0;
        $this->sigid    = $data['sigid']    ?? '';
        $this->signame  = $data['sn']       ?? '';
    }

    /**
     * Get snippet
     * @return string
     */
    public function getSnippet()
    {
        return $this->snippet;
    }

    /**
     * Get signature id
     * @return string
     */
    public function getSigid()
    {
        return $this->sigid;
    }

    /**
     * Get position where we detected malware
     * @return int
     */
    public function getPos()
    {
        return $this->pos;
    }

    /**
     * Get signature name
     * @return string
     */
    public function getSigname()
    {
        return $this->signame;
    }
}

/**
 * Class to store data of detected black/unknown urls
 */
class MDSUrlResult
{
    /**
     * snippet
     * @var string
     */
    private $snippet;

    /**
     * url
     * @var string
     */
    private $sigid;

    /**
     * position
     * @var int
     */
    private $pos;

    /**
     * flag url black
     * @var bool
     */
    private $black;

    /**
     * @var bool
     * flag url unknown
     */
    private $unknown;

    /**
     * @param $data
     */
    public function __construct(array $data)
    {
        $this->snippet  = $data['content']  ?? '';
        $this->pos      = $data['pos']      ?? 0;
        $this->sigid    = $data['sigid']    ?? '';
        $this->black    = $data['black']    ?? false;
        $this->unknown  = $data['unknown']  ?? false;
    }

    /**
     * Get snippet
     * @return string
     */
    public function getSnippet()
    {
        return $this->snippet;
    }

    /**
     * Get signature (detected url)
     * @return string
     */
    public function getSigid()
    {
        return $this->sigid;
    }

    /**
     * Get position where we detected url
     * @return int
     */
    public function getPos()
    {
        return $this->pos;
    }

    /**
     * Get flag is url black
     * @return bool
     */
    public function isBlack()
    {
        return $this->black;
    }

    /**
     * Get flag is url unknown
     * @return bool
     */
    public function isUnknown()
    {
        return $this->unknown;
    }
}

/**
 * Class to get mysqli default socket name
 */
class MDSUnixSocket
{
    /**
     * Default mysql socket paths
     * @var string[]
     */
    private static $sockets_def = [
        '/var/lib/mysql/mysql.sock',
        '/var/run/mysqld/mysqld.sock',
    ];

    /**
     * Default mysql configs paths
     * @var string[]
     */
    private static $cnf_paths_def = [
        '/etc/my.cnf',
        '/etc/mysql/my.cnf'
    ];

    /**
     * Check sockets if it's my related to mysql and use it in mysqli.default_socket
     */
    public static function setDefaultSocket()
    {
        foreach (self::getPossibleSockets() as $file) {
            if (self::checkMysqlSocket($file)) {
                ini_set('mysqli.default_socket', $file);
                break;
            }
        }
    }

    /**
     * Get list of all possible mysql sockets in system
     * @return array
     */
    private static function getPossibleSockets()
    {
        $sockets = array_filter(array_unique(array_merge(
            self::getMysqlSocketFromLsof(),
            self::getSocketFromMysqlCnf(self::$cnf_paths_def),
            self::$sockets_def))
        );
        return $sockets;
    }

    /**
     * Check path that it's mysql related socket
     * @param $file
     * @return bool
     */
    private static function checkMysqlSocket($file)
    {
        if ($file === '' || !file_exists($file) || !is_readable($file)
            || !is_writable($file) || is_file($file)
            || is_dir($file) || is_link($file)
        ) {
            return false;
        }
        $sock = fsockopen('unix://' . $file);
        stream_set_blocking($sock, false);
        $data = fread($sock, 64);
        fclose($sock);
        $proto = @unpack('C/x/x/x/C', substr($data, 0, 5))[1];
        if ($proto < 9 || $proto > 20) {
            return false;
        }
        $banner = @unpack('Z*', $data, 5)[1];
        if (strlen($banner) < 10 && !ctype_alnum(str_replace(['@', '.', '-', '_', '/'], '', $banner))) {
            return false;
        }
        return true;
    }

    /**
     * Try to parse default mysql config paths and get socket from there
     * @param $files
     * @return array
     */
    private static function getSocketFromMysqlCnf($files)
    {
        $sockets = [];
        foreach ($files as $file) {
            if (!@is_readable($file)) {
                continue;
            }
            $cnf = @file_get_contents($file);
            if (preg_match('~socket\s*=\s*([^\n]+)~m', $cnf, $m) && !empty($m[1])) {
                $sockets[] = $m[1];
            }
            if (!is_dir($file . '.d')) {
                continue;
            }
            foreach(scandir($file . '.d') as $cnf_file) {
                if ($cnf_file === '.' || $cnf_file === '..') {
                    continue;
                }
                $cnf = file_get_contents($file . '.d/' . $cnf_file);
                if (preg_match('~socket\s*=\s*([^\n]+)~m', $cnf, $m) && !empty($m[1])) {
                    $sockets[] = $m[1];
                }
            }
        }
        return $sockets;
    }

    /**
     * Get list of possible mysql sockets through lsof
     * @return array|string[]
     */
    private static function getMysqlSocketFromLsof()
    {
        $socket_out = @shell_exec('lsof -U 2>/dev/null|grep mysql|awk \'$9 ~ /^\// {print $9}\'|uniq');
        $sockets = @explode("\n", $socket_out);
        if (empty($sockets)) {
            return [];
        }
        return $sockets;
    }
}

class LoadSignaturesForClean
{
    private $sig_db             = [];
    private $sig_db_meta_info   = [];
    private $sig_db_location    = 'internal';
    private $scan_db            = null;
    public  $_FlexDBShe         = [];

    private $deMapper           = '';

    public function __construct($signature, $avdb)
    {

        $this->sig_db_meta_info = [
            'build-date'    => 'n/a',
            'version'       => 'n/a',
            'release-type'  => 'n/a',
        ];

        if ($signature) {
            $db_raw                 = explode("\n", trim(base64_decode(trim($signature))));
            $this->sig_db_location  = 'external';
        } elseif (file_exists($avdb)) {
            $db_raw                 = explode("\n", trim(@gzinflate(base64_decode(str_rot13(strrev(trim(file_get_contents($avdb))))))));
            $this->sig_db_location  = 'external';
            echo "Loaded External DB\n";
        } else {
            InternalCleanSignatures::init();
            $db_raw = explode("\n", base64_decode(strrev(str_rot13(gzinflate(base64_decode(InternalCleanSignatures::$db))))));
        }
        
        foreach ($db_raw as $line) {
            $line = trim($line);
            if ($line == '') {
                continue;
            }

            $parsed = preg_split("/\t+/", $line);

            if ($parsed[0] == 'System-Data') {
                $meta_info                              = json_decode($parsed[3], true);
                $this->sig_db_meta_info['build-date']   = $meta_info['build-date'];
                $this->sig_db_meta_info['version']      = $meta_info['version'];
                $this->sig_db_meta_info['release-type'] = $meta_info['release-type'];
            } else {
                $db_item['id']          = $parsed[0];
                $db_item['mask_type']   = $parsed[1];

                $db_item['mask_type']   = str_replace('*.', '.*\.', $db_item['mask_type']);
                $db_item['mask_type']   = str_replace('PROCU_ANY', '.*', $db_item['mask_type']);
                $db_item['mask_type']   = str_replace('PROCU_PHP', '\.(suspected|vir|txt|phtml|pht|php\d*|php\..*)$', $db_item['mask_type']);
                $db_item['mask_type']   = str_replace('PROCU_HTML', '\.(htm|html|tpl|inc)$', $db_item['mask_type']);
                $db_item['mask_type']   = str_replace('PROCU_JS', '\.(js)$', $db_item['mask_type']);
                $db_item['mask_type']   = str_replace('PROCU_SS', '.*', $db_item['mask_type']);

                $db_item['sig_type']    = (int)$parsed[2];
                $db_item['sig_match']   = str_replace('~', '\~', trim($parsed[3]));
                $db_item['sig_match']   = str_replace('@<v>@', '\$[a-zA-Z0-9_]+', $db_item['sig_match']);
                $db_item['sig_match']   = str_replace('@<id>@', '[a-zA-Z0-9_]+', $db_item['sig_match']);
                $db_item['sig_match']   = str_replace('@<d>@', '\d+', $db_item['sig_match']);
                $db_item['sig_match']   = str_replace('@<qq>@', '[\'"]', $db_item['sig_match']);
                $db_item['sig_match']   = str_replace('@<q>@', '[\'"]{0,1}', $db_item['sig_match']);
                $db_item['sig_replace'] = trim(@$parsed[4]);

                if ($db_item['sig_match'] == '') {
                    throw new Exception($line);
                }

                $this->sig_db[] = $db_item;
                $this->_FlexDBShe[] = $db_item['sig_match'];  //rescan signs
            }
        }
        LoadSignaturesForScan::optSig($this->_FlexDBShe, false, 'AibolitHelpers::myCheckSum');
        $this->deMapper = @unserialize(@base64_decode($this->deMapper));
    }
    
    public function getDBLocation()
    {
        return $this->sig_db_location;
    }

    public function getDB()
    {
        return $this->sig_db;
    }
    
    public function getDBMetaInfo()
    {
        return $this->sig_db_meta_info;
    }

    public function getDeMapper()
    {
        return is_array($this->deMapper) ? $this->deMapper : false;
    }

    public function getScanDB()
    {
        return $this->scan_db;
    }

    public function setScanDB($db)
    {
        $this->scan_db = $db;
    }
}

class InternalCleanSignatures
{
    public static $db;

    public static function init()
    {
        $i000101010010110010 = '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'; //This variable will be filled by the building script.
        self::$db = $i000101010010110010;
    }
}
class ImLicense
{
    const VERIFY_FIELDS = ['id', 'status', 'group', 'limit', 'token_created_utc', 'token_expire_utc'];
    private $is_valid = false;
    private $raw_lic = [];
    private $valid_sign = '';
    private $pub_key = '';
    private $lic_path = '';
    private $pub_key_path = '';

    public function __construct($lic_path, $pub_key)
    {
        $this->lic_path = $lic_path;
        $this->pub_key_path = $pub_key;

        if (file_exists($lic_path) && filesize($lic_path) > 0 && is_readable($lic_path)) {
            $this->raw_lic = json_decode(file_get_contents($lic_path), true);
        }

        if (file_exists($pub_key) && filesize($pub_key) > 0 && is_readable($pub_key)) {
            $this->pub_key = file_get_contents($pub_key);
        }
        if ($this->isAllFieldsPresent()) {
            $this->findValidSignature();
        }
    }

    public function isValid()
    {
        return $this->is_valid;
    }

    public function getLicData()
    {
        if (!$this->is_valid || $this->valid_sign === '') {
            return false;
        }
        if (is_array($this->raw_lic) && $this->isAllFieldsPresent()) {
            return [
                'id'                => $this->raw_lic['id'],
                'status'            => $this->raw_lic['status'],
                'limit'             => $this->raw_lic['limit'],
                'token_created_utc' => $this->raw_lic['token_created_utc'],
                'token_expire_utc'  => $this->raw_lic['token_expire_utc'],
                'sign'              => $this->valid_sign,
            ];
        }
        return false;
    }

    private function isAllFieldsPresent()
    {
        if (!isset($this->raw_lic['signatures'])) {
            return false;
        }
        if ($this->pub_key === '') {
            return false;
        }
        foreach (self::VERIFY_FIELDS as $field) {
            if (!isset($this->raw_lic[$field])) {
                return false;
            }
        }
        return true;
    }

    private function findValidSignature()
    {
        foreach ($this->raw_lic['signatures'] as $sign) {
            $signature = base64_decode($sign);
            $content = '';
            foreach (self::VERIFY_FIELDS as $field) {
                $content .= $this->raw_lic[$field];
            }
            if (openssl_verify($content, $signature, $this->pub_key, OPENSSL_ALGO_SHA512)) {
                $this->valid_sign = $sign;
                $this->is_valid = true;
                return true;
            }
        }
        return false;
    }
}

class LoadSignaturesForScan
{
    private $sig_db             = [];
    private $sig_db_meta_info   = [];
    private $sig_db_location    = 'internal';

    private $mode;
    private $debug;

    public $_DBShe;
    public $X_DBShe;
    public $_FlexDBShe;
    public $X_FlexDBShe;
    public $XX_FlexDBShe;
    public $_ExceptFlex;
    public $_AdwareSig;
    public $_PhishingSig;
    public $_JSVirSig;
    public $X_JSVirSig;
    public $_SusDB;
    public $_SusDBPrio;
    public $_DeMapper;
    public $_Mnemo;

    public $whiteUrls;
    public $blackUrls;
    public $ownUrl = null;

    private $count;
    private $count_susp;
    private $result = 0;
    private $last_error = '';

    const SIGN_INTERNAL = 1;
    const SIGN_EXTERNAL = 2;
    const SIGN_IMPORT = 3;
    const SIGN_ERROR = 9;

    public function __construct($avdb_file, $mode, $debug)
    {
        $this->mode = $mode;
        $this->debug = $debug;
        $this->sig_db_meta_info = [
            'build-date'    => 'n/a',
            'version'       => 'n/a',
            'release-type'  => 'n/a',
        ];

        if ($avdb_file && file_exists($avdb_file)) {
            $avdb = explode("\n", gzinflate(base64_decode(str_rot13(strrev(trim(file_get_contents($avdb_file)))))));
            $this->sig_db_location  = 'external';

            $this->_DBShe       = explode("\n", base64_decode($avdb[0]));
            $this->X_DBShe      = explode("\n", base64_decode($avdb[1]));
            $this->_FlexDBShe   = explode("\n", base64_decode($avdb[2]));
            $this->X_FlexDBShe  = explode("\n", base64_decode($avdb[3]));
            $this->XX_FlexDBShe = explode("\n", base64_decode($avdb[4]));
            $this->_ExceptFlex  = explode("\n", base64_decode($avdb[5]));
            $this->_AdwareSig   = explode("\n", base64_decode($avdb[6]));
            $this->_PhishingSig = explode("\n", base64_decode($avdb[7]));
            $this->_JSVirSig    = explode("\n", base64_decode($avdb[8]));
            $this->X_JSVirSig   = explode("\n", base64_decode($avdb[9]));
            $this->_SusDB       = explode("\n", base64_decode($avdb[10]));
            $this->_SusDBPrio   = explode("\n", base64_decode($avdb[11]));
            $this->_DeMapper    = array_combine(explode("\n", base64_decode($avdb[12])), explode("\n", base64_decode($avdb[13])));
            $this->_Mnemo       = @array_flip(@array_combine(explode("\n", base64_decode($avdb[14])), explode("\n", base64_decode($avdb[15])))); //TODO: you need to remove array_flip and swap the keys and values in array_combine. Write a test: put the signature base in the tests folder and run a scan with this base on the VIRII folder - the result should not change, since the base is the same

            // get meta information
            $avdb_meta_info = json_decode(base64_decode($avdb[16]), true);

            $this->sig_db_meta_info['build-date'] = $avdb_meta_info ? $avdb_meta_info['build-date'] : 'n/a';
            $this->sig_db_meta_info['version'] = $avdb_meta_info ? $avdb_meta_info['version'] : 'n/a';
            $this->sig_db_meta_info['release-type'] = $avdb_meta_info ? $avdb_meta_info['release-type'] : 'n/a';

            if (count($this->_DBShe) <= 1) {
                $this->_DBShe = [];
            }

            if (count($this->X_DBShe) <= 1) {
                $this->X_DBShe = [];
            }

            if (count($this->_FlexDBShe) <= 1) {
                $this->_FlexDBShe = [];
            }

            if (count($this->X_FlexDBShe) <= 1) {
                $this->X_FlexDBShe = [];
            }

            if (count($this->XX_FlexDBShe) <= 1) {
                $this->XX_FlexDBShe = [];
            }

            if (count($this->_ExceptFlex) <= 1) {
                $this->_ExceptFlex = [];
            }

            if (count($this->_AdwareSig) <= 1) {
                $this->_AdwareSig = [];
            }

            if (count($this->_PhishingSig) <= 1) {
                $this->_PhishingSig = [];
            }

            if (count($this->X_JSVirSig) <= 1) {
                $this->X_JSVirSig = [];
            }

            if (count($this->_JSVirSig) <= 1) {
                $this->_JSVirSig = [];
            }

            if (count($this->_SusDB) <= 1) {
                $this->_SusDB = [];
            }

            if (count($this->_SusDBPrio) <= 1) {
                $this->_SusDBPrio = [];
            }

            $this->result = self::SIGN_EXTERNAL;
        } else {
            InternalSignatures::init();
            $this->_DBShe       = InternalSignatures::$_DBShe;
            $this->X_DBShe      = InternalSignatures::$X_DBShe;
            $this->_FlexDBShe   = InternalSignatures::$_FlexDBShe;
            $this->X_FlexDBShe  = InternalSignatures::$X_FlexDBShe;
            $this->XX_FlexDBShe = InternalSignatures::$XX_FlexDBShe;
            $this->_ExceptFlex  = InternalSignatures::$_ExceptFlex;
            $this->_AdwareSig   = InternalSignatures::$_AdwareSig;
            $this->_PhishingSig = InternalSignatures::$_PhishingSig;
            $this->_JSVirSig    = InternalSignatures::$_JSVirSig;
            $this->X_JSVirSig   = InternalSignatures::$X_JSVirSig;
            $this->_SusDB       = InternalSignatures::$_SusDB;
            $this->_SusDBPrio   = InternalSignatures::$_SusDBPrio;
            $this->_DeMapper    = InternalSignatures::$_DeMapper;
            $this->_Mnemo       = InternalSignatures::$_Mnemo;

            // get meta information
            $avdb_meta_info = InternalSignatures::$db_meta_info;

            $this->sig_db_meta_info['build-date'] = $avdb_meta_info ? $avdb_meta_info['build-date'] : 'n/a';
            $this->sig_db_meta_info['version'] = $avdb_meta_info ? $avdb_meta_info['version'] : 'n/a';
            $this->sig_db_meta_info['release-type'] = $avdb_meta_info ? $avdb_meta_info['release-type'] : 'n/a';

            $this->result = self::SIGN_INTERNAL;
        }

        // use only basic signature subset
        if ($mode < 2) {
            $this->X_FlexDBShe  = [];
            $this->XX_FlexDBShe = [];
            $this->X_JSVirSig   = [];
        }

        // Load custom signatures
        if (file_exists(__DIR__ . '/ai-bolit.sig')) {
            try {
                $s_file = new SplFileObject(__DIR__ . '/ai-bolit.sig');
                $s_file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
                foreach ($s_file as $line) {
                    $this->_FlexDBShe[] = preg_replace('#\G(?:[^~\\\\]+|\\\\.)*+\K~#', '\\~', $line); // escaping ~
                }

                $this->result = self::SIGN_IMPORT;
                $s_file = null; // file handler is closed
            }
            catch (Exception $e) {
                $this->result = self::SIGN_ERROR;
                $this->last_error = $e->getMessage();
            }
        }

        $this->count = count($this->_JSVirSig) + count($this->X_JSVirSig) + count($this->_DBShe) + count($this->X_DBShe) + count($this->_FlexDBShe) + count($this->X_FlexDBShe) + count($this->XX_FlexDBShe);
        $this->count_susp = $this->count + count($this->_SusDB);

        if (!$debug) {
            $this->OptimizeSignatures($debug);
        }

        $this->_DBShe  = array_map('strtolower', $this->_DBShe);
        $this->X_DBShe = array_map('strtolower', $this->X_DBShe);
    }

    private function OptimizeSignatures($debug)
    {
        ($this->mode == 2) && ($this->_FlexDBShe = array_merge($this->_FlexDBShe, $this->X_FlexDBShe, $this->XX_FlexDBShe));
        ($this->mode == 1) && ($this->_FlexDBShe = array_merge($this->_FlexDBShe, $this->X_FlexDBShe));
        $this->X_FlexDBShe = $this->XX_FlexDBShe = [];

        ($this->mode == 2) && ($this->_JSVirSig = array_merge($this->_JSVirSig, $this->X_JSVirSig));
        $this->X_JSVirSig = [];

        $count = count($this->_FlexDBShe);

        for ($i = 0; $i < $count; $i++) {
            if ($this->_FlexDBShe[$i] == '[a-zA-Z0-9_]+?\(\s*[a-zA-Z0-9_]+?=\s*\)')
                $this->_FlexDBShe[$i] = '\((?<=[a-zA-Z0-9_].)\s*[a-zA-Z0-9_]++=\s*\)';
            if ($this->_FlexDBShe[$i] == '([^\?\s])\({0,1}\.[\+\*]\){0,1}\2[a-z]*e')
                $this->_FlexDBShe[$i] = '(?J)\.[+*](?<=(?<d>[^\?\s])\(..|(?<d>[^\?\s])..)\)?\g{d}[a-z]*e';
            if ($this->_FlexDBShe[$i] == '$[a-zA-Z0-9_]\{\d+\}\s*\.$[a-zA-Z0-9_]\{\d+\}\s*\.$[a-zA-Z0-9_]\{\d+\}\s*\.')
                $this->_FlexDBShe[$i] = '\$[a-zA-Z0-9_]\{\d+\}\s*\.\$[a-zA-Z0-9_]\{\d+\}\s*\.\$[a-zA-Z0-9_]\{\d+\}\s*\.';

            $this->_FlexDBShe[$i] = str_replace('http://.+?/.+?\.php\?a', 'http://[^?\s]++(?<=\.php)\?a', $this->_FlexDBShe[$i]);
            $this->_FlexDBShe[$i] = preg_replace('~\[a-zA-Z0-9_\]\+\K\?~', '+', $this->_FlexDBShe[$i]);
            $this->_FlexDBShe[$i] = preg_replace('~^\\\\[d]\+&@~', '&@(?<=\d..)', $this->_FlexDBShe[$i]);
            $this->_FlexDBShe[$i] = str_replace('\s*[\'"]{0,1}.+?[\'"]{0,1}\s*', '.+?', $this->_FlexDBShe[$i]);
            $this->_FlexDBShe[$i] = str_replace('[\'"]{0,1}.+?[\'"]{0,1}', '.+?', $this->_FlexDBShe[$i]);

            $this->_FlexDBShe[$i] = preg_replace('~^\[\'"\]\{0,1\}\.?|^@\*|^\\\\s\*~', '', $this->_FlexDBShe[$i]);
        }

        self::optSig($this->_FlexDBShe,     $debug, 'AibolitHelpers::myCheckSum');
        self::optSig($this->_JSVirSig,      $debug, 'AibolitHelpers::myCheckSum');
        self::optSig($this->_AdwareSig,     $debug, 'AibolitHelpers::myCheckSum');
        self::optSig($this->_PhishingSig,   $debug, 'AibolitHelpers::myCheckSum');
        self::optSig($this->_SusDB,         $debug, 'AibolitHelpers::myCheckSum');
        //optSig($g_SusDBPrio);
        //optSig($g_ExceptFlex);

        // convert exception rules
        $cnt = count($this->_ExceptFlex);
        for ($i = 0; $i < $cnt; $i++) {
            $this->_ExceptFlex[$i] = trim(Normalization::normalize($this->_ExceptFlex[$i]));
            if ($this->_ExceptFlex[$i] == '')
                unset($this->_ExceptFlex[$i]);
        }

        $this->_ExceptFlex = array_values($this->_ExceptFlex);
    }

    public static function optSig(&$sigs, $debug = false, $func_id = null)
    {
        $sigs = array_unique($sigs);

        // Add SigId
        foreach ($sigs as $k => &$s) {
            if ($func_id && is_callable($func_id)) {
                $id = $func_id($s);
            } else {
                $id = $k;
            }
            $s .= '(?<X' . $id . '>)';
        }
        unset($s);

        $fix = [
            '([^\?\s])\({0,1}\.[\+\*]\){0,1}\2[a-z]*e' => '(?J)\.[+*](?<=(?<d>[^\?\s])\(..|(?<d>[^\?\s])..)\)?\g{d}[a-z]*e',
            'http://.+?/.+?\.php\?a' => 'http://[^?\s]++(?<=\.php)\?a',
            '\s*[\'"]{0,1}.+?[\'"]{0,1}\s*' => '.+?',
            '[\'"]{0,1}.+?[\'"]{0,1}' => '.+?'
        ];

        $sigs = str_replace(array_keys($fix), array_values($fix), $sigs);

        $fix = [
            '~^\\\\[d]\+&@~' => '&@(?<=\d..)',
            '~^((\[\'"\]|\\\\s|@)(\{0,1\}\.?|[?*]))+~' => ''
        ];

        $sigs = preg_replace(array_keys($fix), array_values($fix), $sigs);

        self::optSigCheck($sigs, $debug);

        $tmp = [];
        foreach ($sigs as $i => $s) {
            if (!preg_match('~^(?>(?!\.[*+]|\\\\\d)(?:\\\\.|\[.+?\]|.))+$~', $s)) {
                unset($sigs[$i]);
                $tmp[] = $s;
            }
        }

        usort($sigs, 'strcasecmp');
        $txt = implode("\n", $sigs);

        for ($i = 24; $i >= 1; ($i > 4) ? $i -= 4 : --$i) {
            $txt = preg_replace_callback('#^((?>(?:\\\\.|\\[.+?\\]|[^(\n]|\((?:\\\\.|[^)(\n])++\))(?:[*?+]\+?|\{\d+(?:,\d*)?\}[+?]?|)){' . $i . ',})[^\n]*+(?:\\n\\1(?![{?*+]).+)+#im', 'LoadSignaturesForScan::optMergePrefixes', $txt);
        }

        $sigs = array_merge(explode("\n", $txt), $tmp);

        self::optSigCheck($sigs, $debug);
    }

    private static function optMergePrefixes($m)
    {
        $limit = 8000;

        $prefix     = $m[1];
        $prefix_len = strlen($prefix);

        $len = $prefix_len;
        $r   = [];

        $suffixes = [];
        foreach (explode("\n", $m[0]) as $line) {

            if (strlen($line) > $limit) {
                $r[] = $line;
                continue;
            }

            $s = substr($line, $prefix_len);
            $len += strlen($s);
            if ($len > $limit) {
                if (count($suffixes) == 1) {
                    $r[] = $prefix . $suffixes[0];
                } else {
                    $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
                }
                $suffixes = [];
                $len      = $prefix_len + strlen($s);
            }
            $suffixes[] = $s;
        }

        if (!empty($suffixes)) {
            if (count($suffixes) == 1) {
                $r[] = $prefix . $suffixes[0];
            } else {
                $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
            }
        }

        return implode("\n", $r);
    }

    private function optMergePrefixes_Old($m)
    {
        $prefix     = $m[1];
        $prefix_len = strlen($prefix);

        $suffixes = [];
        foreach (explode("\n", $m[0]) as $line) {
            $suffixes[] = substr($line, $prefix_len);
        }

        return $prefix . '(?:' . implode('|', $suffixes) . ')';
    }

    /*
     * Checking errors in pattern
     */
    private static function optSigCheck(&$sigs, $debug)
    {
        $result = true;

        foreach ($sigs as $k => $sig) {
            if (trim($sig) == "") {
                if ($debug) {
                    echo ("************>>>>> EMPTY\n     pattern: " . $sig . "\n");
                }
                unset($sigs[$k]);
                $result = false;
            }

            if (@preg_match('~' . $sig . '~smiS', '') === false) {
                $error = error_get_last();
                if ($debug) {
                    echo ("************>>>>> " . $error['message'] . "\n     pattern: " . $sig . "\n");
                }
                unset($sigs[$k]);
                $result = false;
            }
        }

        return $result;
    }

    public static function getSigId($l_Found)
    {
        foreach ($l_Found as $key => &$v) {
            if (is_string($key) && $v[1] != -1 && strlen($key) == 9) {
                return substr($key, 1);
            }
        }

        return null;
    }

    public function setOwnUrl($url)
    {
        if (isset($this->blackUrls)) {
            foreach ($this->blackUrls->getDb() as $black) {
                if (preg_match('~' . $black . '~msi', $url)) {
                    $this->ownUrl = null;
                    return;
                }
            }
        }
        $this->ownUrl = $url;
    }

    public function getOwnUrl()
    {
        return $this->ownUrl;
    }

    public function getDBLocation()
    {
        return $this->sig_db_location;
    }

    public function getDB()
    {
        return $this->sig_db;
    }

    public function getDBMetaInfo()
    {
        return $this->sig_db_meta_info;
    }

    public function getDBMetaInfoVersion()
    {
        return $this->sig_db_meta_info['version'];
    }

    public function getDBCount()
    {
        return $this->count;
    }

    public function getDBCountWithSuspicious()
    {
        return $this->count_susp;
    }

    public function getResult()
    {
        return $this->result;
    }

    public function getLastError()
    {
        return $this->last_error;
    }
}

class InternalSignatures
{
    public static $_DBShe;
    public static $X_DBShe;
    public static $_FlexDBShe;
    public static $X_FlexDBShe;
    public static $XX_FlexDBShe;
    public static $_ExceptFlex;
    public static $_AdwareSig;
    public static $_PhishingSig;
    public static $_JSVirSig;
    public static $X_JSVirSig;
    public static $_SusDB;
    public static $_SusDBPrio;
    public static $_DeMapper;
    public static $_Mnemo;
    public static $db_meta_info;

    public static function init()
    {
        //BEGIN_SIG 14/12/2021 08:24:01
self::$_DBShe = unserialize(gzinflate(/*1639502641*/base64_decode("S7QysKquBQA=")));
self::$X_DBShe = unserialize(gzinflate(/*1639502641*/base64_decode("S7QysKquBQA=")));
self::$_FlexDBShe = unserialize(gzinflate(/*1639502641*/base64_decode("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")));
self::$X_FlexDBShe = unserialize(gzinflate(/*1639502641*/base64_decode("S7QysKquBQA=")));
self::$XX_FlexDBShe = unserialize(gzinflate(/*1639502641*/base64_decode("S7QysKquBQA=")));
self::$_ExceptFlex = unserialize(gzinflate(/*1639502641*/base64_decode("S7QysKquBQA=")));
self::$_AdwareSig = unserialize(gzinflate(/*1639502641*/base64_decode("S7QysKquBQA=")));
self::$_PhishingSig = unserialize(gzinflate(/*1639502641*/base64_decode("S7QysKquBQA=")));
self::$_JSVirSig = unserialize(gzinflate(/*1639502641*/base64_decode("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")));
self::$X_JSVirSig = unserialize(gzinflate(/*1639502641*/base64_decode("S7QysKquBQA=")));
self::$_SusDB = unserialize(gzinflate(/*1639502641*/base64_decode("HUu7DsIwEPuXTKRDQiuV4QJ0YOEHmAhDaSM4Kb1ESWkG4N+5Ivkh23IPDbwRtiZDW4PY5yFhnI82V0uf7LOakNzqBya5wnoKSGdcnFWXzNNdGISa77sWBGi96aCUYpXsrk25cWLQy3s3fkIaY3I5R6SHtGoI01r5f2cVuVlqYb4/")));
self::$_SusDBPrio = unserialize(gzinflate(/*1639502641*/base64_decode("S7QysKquBQA=")));
self::$_Mnemo = unserialize(gzinflate(/*1639502641*/base64_decode("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")));
self::$_DeMapper = unserialize(base64_decode("YTo1OntzOjEwOiJ3aXphcmQucGhwIjtzOjM3OiJjbGFzcyBXZWxjb21lU3RlcCBleHRlbmRzIENXaXphcmRTdGVwIjtzOjE3OiJ1cGRhdGVfY2xpZW50LnBocCI7czozNzoieyBDVXBkYXRlQ2xpZW50OjpBZGRNZXNzYWdlMkxvZygiZXhlYyI7czoxMToiaW5jbHVkZS5waHAiO3M6NDg6IkdMT0JBTFNbIlVTRVIiXS0+SXNBdXRob3JpemVkKCkgJiYgJGFyQXV0aFJlc3VsdCI7czo5OiJzdGFydC5waHAiO3M6NjA6IkJYX1JPT1QuJy9tb2R1bGVzL21haW4vY2xhc3Nlcy9nZW5lcmFsL3VwZGF0ZV9kYl91cGRhdGVyLnBocCI7czoxMDoiaGVscGVyLnBocCI7czo1ODoiSlBsdWdpbkhlbHBlcjo6Z2V0UGx1Z2luKCJzeXN0ZW0iLCJvbmVjbGlja2NoZWNrb3V0X3ZtMyIpOyI7fQ=="));
self::$db_meta_info = unserialize(base64_decode("YTozOntzOjEwOiJidWlsZC1kYXRlIjtzOjEwOiIxNjM5NDY3OTUzIjtzOjc6InZlcnNpb24iO3M6MTM6IjIwMjExMjE0LTcwMzgiO3M6MTI6InJlbGVhc2UtdHlwZSI7czoxMDoicHJvZHVjdGlvbiI7fQ=="));

//END_SIG
    }
}

class AibolitHelpers
{
    /**
     * Format bytes to human readable
     *
     * @param int $bytes
     *
     * @return string
     */
    public static function bytes2Human($bytes)
    {
        if ($bytes < 1024) {
            return $bytes . ' b';
        } elseif (($kb = $bytes / 1024) < 1024) {
            return number_format($kb, 2) . ' Kb';
        } elseif (($mb = $kb / 1024) < 1024) {
            return number_format($mb, 2) . ' Mb';
        } elseif (($gb = $mb / 1024) < 1024) {
            return number_format($gb, 2) . ' Gb';
        } else {
            return number_format($gb / 1024, 2) . 'Tb';
        }
    }

    /**
     * Seconds to human readable
     * @param int $seconds
     * @return string
     */
    public static function seconds2Human($seconds)
    {
        $r        = '';
        $_seconds = floor($seconds);
        $ms       = $seconds - $_seconds;
        $seconds  = $_seconds;
        if ($hours = floor($seconds / 3600)) {
            $r .= $hours . ' h ';
            $seconds %= 3600;
        }

        if ($minutes = floor($seconds / 60)) {
            $r .= $minutes . ' m ';
            $seconds %= 60;
        }

        if ($minutes < 3) {
            $r .= ' ' . (string)($seconds + ($ms > 0 ? round($ms) : 0)) . ' s';
        }

        return $r;
    }

    /**
     * Get bytes from shorthand byte values (1M, 1G...)
     * @param int|string $val
     * @return int
     */
    public static function getBytes($val)
    {
        $val  = trim($val);
        $last = strtolower($val[strlen($val) - 1]);
        $val  = preg_replace('~\D~', '', $val);
        switch ($last) {
            case 't':
                $val *= 1024;
            case 'g':
                $val *= 1024;
            case 'm':
                $val *= 1024;
            case 'k':
                $val *= 1024;
        }
        return intval($val);
    }

    /**
     * Convert dangerous chars to html entities
     *
     * @param        $par_Str
     * @param string $addPrefix
     * @param string $noPrefix
     * @param bool   $replace_path
     *
     * @return string
     */
    public static function makeSafeFn($par_Str, $addPrefix = '', $noPrefix = '', $replace_path = false)
    {
        if ($replace_path) {
            $lines = explode("\n", $par_Str);
            array_walk($lines, static function(&$n) use ($addPrefix, $noPrefix) {
                $n = $addPrefix . str_replace($noPrefix, '', $n);
            });

            $par_Str = implode("\n", $lines);
        }

        return htmlspecialchars($par_Str, ENT_SUBSTITUTE | ENT_QUOTES);
    }


    public static function myCheckSum($str)
    {
        return hash('crc32b', $str);
    }

}

class Finder
{
    const MAX_ALLOWED_PHP_HTML_IN_DIR = 600;

    private $sym_links              = [];
    private $skipped_folders        = [];
    private $doorways               = [];
    private $big_files              = [];
    private $big_elf_files          = [];

    private $collect_skipped        = false;
    private $collect_symLinks       = false;
    private $collect_doorways       = false;
    private $collect_bigfiles       = false;
    private $collect_bigelffiles    = false;

    private $total_dir_counter      = 0;
    private $total_files_counter    = 0;
    private $checked_hashes         = [];

    private $initial_dir            = '';
    private $initial_level          = null;
    private $level_limit            = null;

    private $filter;
    private $total                  = 0;

    public function __construct($filter = null, $level_limit = null)
    {
        $this->filter = $filter;
        $this->level_limit = $level_limit;
    }

    private function linkResolve($path)
    {
        return realpath($path);
    }

    private function resolve($path, $follow_symlinks)
    {
        if (!$follow_symlinks || !is_link($path)) {
            return $path;
        }
        return $this->linkResolve($path);
    }

    private function isPathCheckedAlready($path)
    {
        $root_hash = crc32($path);
        if (isset($this->checked_hashes[$root_hash])) {
            return true;
        }
        $this->checked_hashes[$root_hash] = '';
        return false;
    }

    private function walk($path, $follow_symlinks)
    {
        $level = substr_count($path, '/');
        if (isset($this->level_limit) && (($level - $this->initial_level + 1) > $this->level_limit)) {
            return;
        }
        $l_DirCounter          = 0;
        $l_DoorwayFilesCounter = 0;

        if ($follow_symlinks && $this->isPathCheckedAlready($path)) {
            return;
        }

        # will not iterate dir, if it should be ignored
        if (!$this->filter->needToScan($path, false, true)) {
            if ($this->collect_skipped) {
                $this->skipped_folders[] = $path;
            }
            return;
        }
        $dirh = @opendir($path);
        if ($dirh === false) {
            return;
        }

        while (($entry = readdir($dirh)) !== false) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $entry = $path . DIRECTORY_SEPARATOR . $entry;
            if (is_link($entry)) {

                if ($this->collect_symLinks) {
                    $this->sym_links[] = $entry;
                }

                if (!$follow_symlinks) {
                    continue;
                }
                $real_path = $this->resolve($entry, true);
            } else {
                $real_path = realpath($entry);
            }
            if (is_dir($entry)) {
                $l_DirCounter++;
                if ($this->collect_doorways && $l_DirCounter > self::MAX_ALLOWED_PHP_HTML_IN_DIR) {
                    $this->doorways[]  = $path;
                    $l_DirCounter = -655360;
                }
                $this->total_dir_counter++;
                yield from $this->walk($real_path, $follow_symlinks);
            } else if (is_file($entry)) {
                $stat = stat($entry);
                if (!$stat) {
                    continue;
                }
                if ($this->collect_doorways && is_callable([$this->filter, 'checkShortExt']) && $this->filter->checkShortExt($entry)) {
                    $l_DoorwayFilesCounter++;
                    if ($l_DoorwayFilesCounter > self::MAX_ALLOWED_PHP_HTML_IN_DIR) {
                        $this->doorways[]           = $path;
                        $l_DoorwayFilesCounter = -655360;
                    }
                }
                if ($follow_symlinks && $this->isPathCheckedAlready($real_path)) {
                    continue;
                }
                if ($this->collect_bigfiles && is_callable([$this->filter, 'checkIsBig']) && $this->filter->checkIsBig($real_path)) {
                    $this->big_files[] = $real_path;
                }
                if ($this->collect_bigelffiles
                    && is_callable([$this->filter, 'checkIsBig']) && $this->filter->checkIsBig($real_path)
                    && is_callable([$this->filter, 'checkIsElf']) && $this->filter->checkIsElf($real_path)
                    && $this->filter->needToScan($real_path, false, false, ['check_size_range'])
                ) {
                    $this->big_elf_files[] = $real_path;
                }
                $need_to_scan = $this->filter->needToScan($real_path, $stat);
                $this->total_files_counter = $need_to_scan ? $this->total_files_counter + 1 : $this->total_files_counter;
                $this->total++;
                 if (class_exists('Progress')) {
                     Progress::setCurrentFile($real_path);
                     Progress::setFilesTotal($this->total_files_counter);
                     Progress::updateList($this->total);
                }
                if ($need_to_scan) {
                    yield $real_path;
                }
            }
        }
        closedir($dirh);
    }

    private function expandPath($path, $follow_symlinks)
    {
        if ($path) {
            if (is_dir($path)) {
                yield from $this->walk($path, $follow_symlinks);
            } else {
                if ($this->collect_bigfiles && is_callable([$this->filter, 'checkIsBig']) && $this->filter->checkIsBig($path)) {
                    $this->big_files[] = $path;
                    if ($this->collect_bigelffiles && is_callable([$this->filter, 'checkIsElf']) && $this->filter->checkIsElf($path)
                        && $this->filter->needToScan($path, false, false, ['check_size_range'])) {
                        $this->big_elf_files[] = $path;
                    }
                }
                $need_to_scan = $this->filter->needToScan($path);
                if ($need_to_scan) {
                    yield $path;
                }
            }
        }
    }

    public function find($target)
    {
        $started = microtime(true);

        if ($target === '/') {
            $target = '/*';
        }
        if (is_string($target) && substr($target, -1) === DIRECTORY_SEPARATOR) {
            $target = substr($target, 0, -1);
        }

        if (is_callable([$this->filter, 'getGenerated']) && !$this->filter->getGenerated()
            && is_callable([$this->filter, 'generateCheckers'])
        ) {
            $this->filter->generateCheckers();
        }

        if (class_exists('Progress')) {
            Progress::setStage(Progress::STAGE_LIST);
        }

        $paths = is_array($target) ? $target : new GlobIterator($target, FilesystemIterator::CURRENT_AS_PATHNAME);
        foreach ($paths as $path) {
            $this->initial_dir = realpath($path);
            $this->initial_level = substr_count($this->initial_dir, '/');
            $path = $this->resolve($path, $this->filter->isFollowSymlink());
            yield from $this->expandPath($path, $this->filter->isFollowSymlink());
        }

        if (class_exists('PerfomanceStats')) {
            PerfomanceStats::addPerfomanceItem(PerfomanceStats::FINDER_STAT, microtime(true) - $started);
        }
    }

    private function convertTemplatesToRegexp($templates)
    {
        return '~(' . str_replace([',', '.', '*'], ['|', '\\.', '.*'], $templates) . ')~i';
    }

    public function setLevelLimit($level)
    {
        $this->level_limit = $level;
    }

    public function getSymlinks()
    {
        return $this->sym_links;
    }

    public function getBigFiles()
    {
        return $this->big_files;
    }

    public function getBigElfFiles()
    {
        return $this->big_elf_files;
    }

    public function setCollectDoorways($flag)
    {
        $this->collect_doorways = $flag;
    }

    public function setCollectBigElfs($flag)
    {
        $this->collect_bigelffiles = $flag;
    }

    public function setCollectSymlinks($flag)
    {
        $this->collect_symLinks = $flag;
    }

    public function setCollectSkipped($flag)
    {
        $this->collect_skipped = $flag;
    }

    public function setCollectBigFiles($flag)
    {
        $this->collect_bigfiles = $flag;
    }

    public function getDoorways()
    {
        return $this->doorways;
    }

    public function skippedDirs()
    {
        return $this->skipped_folders;
    }

    public function getTotalDirs()
    {
        return $this->total_dir_counter;
    }

    public function getTotalFiles()
    {
        return $this->total_files_counter;
    }

    public function getFilter()
    {
        return $this->filter;
    }
}
class StringToStreamWrapper {

    const WRAPPER_NAME = 'var';

    private static $_content;
    private $_position;

    /**
     * Prepare a new memory stream with the specified content
     * @return string
     */
    public static function prepare($content)
    {
        if (!in_array(self::WRAPPER_NAME, stream_get_wrappers())) {
            stream_wrapper_register(self::WRAPPER_NAME, get_class());
        }
        self::$_content = $content;
    }

    public function stream_open($path, $mode, $options, &$opened_path)
    {
        $this->_position = 0;
        return true;
    }

    public function stream_read($count)
    {
        $ret = substr(self::$_content, $this->_position, $count);
        $this->_position += strlen($ret);
        return $ret;
    }

    public function stream_stat()
    {
        return [];
    }

    public function stream_eof()
    {
        return $this->_position >= strlen(self::$_content);
    }

    public function stream_set_option($option , $arg1, $arg2 )
    {
        return true;
    }
}

class Normalization
{
    const MAX_ITERATION = 10;

    private static $confusables = "YToxNTY1OntzOjM6IuKAqCI7czoxOiIgIjtzOjM6IuKAqSI7czoxOiIgIjtzOjM6IuGagCI7czoxOiIgIjtzOjM6IuKAgCI7czoxOiIgIjtzOjM6IuKAgSI7czoxOiIgIjtzOjM6IuKAgiI7czoxOiIgIjtzOjM6IuKAgyI7czoxOiIgIjtzOjM6IuKAhCI7czoxOiIgIjtzOjM6IuKAhSI7czoxOiIgIjtzOjM6IuKAhiI7czoxOiIgIjtzOjM6IuKAiCI7czoxOiIgIjtzOjM6IuKAiSI7czoxOiIgIjtzOjM6IuKAiiI7czoxOiIgIjtzOjM6IuKBnyI7czoxOiIgIjtzOjI6IsKgIjtzOjE6IiAiO3M6Mzoi4oCHIjtzOjE6IiAiO3M6Mzoi4oCvIjtzOjE6IiAiO3M6Mjoiw4IiO3M6MToiICI7czoyOiLfuiI7czoxOiJfIjtzOjM6Iu+5jSI7czoxOiJfIjtzOjM6Iu+5jiI7czoxOiJfIjtzOjM6Iu+5jyI7czoxOiJfIjtzOjM6IuKAkCI7czoxOiItIjtzOjM6IuKAkSI7czoxOiItIjtzOjM6IuKAkiI7czoxOiItIjtzOjM6IuKAkyI7czoxOiItIjtzOjM6Iu+5mCI7czoxOiItIjtzOjI6ItuUIjtzOjE6Ii0iO3M6Mzoi4oGDIjtzOjE6Ii0iO3M6Mjoiy5ciO3M6MToiLSI7czozOiLiiJIiO3M6MToiLSI7czozOiLinpYiO3M6MToiLSI7czozOiLisroiO3M6MToiLSI7czoyOiLYjSI7czoxOiIsIjtzOjI6ItmrIjtzOjE6IiwiO3M6Mzoi4oCaIjtzOjE6IiwiO3M6MjoiwrgiO3M6MToiLCI7czozOiLqk7kiO3M6MToiLCI7czoyOiLNviI7czoxOiI7IjtzOjM6IuCkgyI7czoxOiI6IjtzOjM6IuCqgyI7czoxOiI6IjtzOjM6Iu+8miI7czoxOiI6IjtzOjI6ItaJIjtzOjE6IjoiO3M6Mjoi3IMiO3M6MToiOiI7czoyOiLchCI7czoxOiI6IjtzOjM6IuGbrCI7czoxOiI6IjtzOjM6Iu+4sCI7czoxOiI6IjtzOjM6IuGggyI7czoxOiI6IjtzOjM6IuGgiSI7czoxOiI6IjtzOjM6IuKBmiI7czoxOiI6IjtzOjI6IteDIjtzOjE6IjoiO3M6Mjoiy7giO3M6MToiOiI7czozOiLqnokiO3M6MToiOiI7czozOiLiiLYiO3M6MToiOiI7czoyOiLLkCI7czoxOiI6IjtzOjM6IuqTvSI7czoxOiI6IjtzOjM6Iu+8gSI7czoxOiIhIjtzOjI6IseDIjtzOjE6IiEiO3M6Mzoi4rWRIjtzOjE6IiEiO3M6MjoiypQiO3M6MToiPyI7czoyOiLJgSI7czoxOiI/IjtzOjM6IuClvSI7czoxOiI/IjtzOjM6IuGOriI7czoxOiI/IjtzOjM6IuqbqyI7czoxOiI/IjtzOjQ6IvCdha0iO3M6MToiLiI7czozOiLigKQiO3M6MToiLiI7czoyOiLcgSI7czoxOiIuIjtzOjI6ItyCIjtzOjE6Ii4iO3M6Mzoi6piOIjtzOjE6Ii4iO3M6NDoi8JCpkCI7czoxOiIuIjtzOjI6ItmgIjtzOjE6Ii4iO3M6Mjoi27AiO3M6MToiLiI7czozOiLqk7giO3M6MToiLiI7czozOiLjg7siO3M6MToityI7czozOiLvvaUiO3M6MToityI7czozOiLhm6siO3M6MToityI7czoyOiLOhyI7czoxOiK3IjtzOjM6IuK4sSI7czoxOiK3IjtzOjQ6IvCQhIEiO3M6MToityI7czozOiLigKIiO3M6MToityI7czozOiLigKciO3M6MToityI7czozOiLiiJkiO3M6MToityI7czozOiLii4UiO3M6MToityI7czozOiLqno8iO3M6MToityI7czozOiLhkKciO3M6MToityI7czoyOiLVnSI7czoxOiInIjtzOjM6Iu+8hyI7czoxOiInIjtzOjM6IuKAmCI7czoxOiInIjtzOjM6IuKAmSI7czoxOiInIjtzOjM6IuKAmyI7czoxOiInIjtzOjM6IuKAsiI7czoxOiInIjtzOjM6IuKAtSI7czoxOiInIjtzOjI6ItWaIjtzOjE6IiciO3M6Mjoi17MiO3M6MToiJyI7czoxOiJgIjtzOjE6IiciO3M6Mzoi4b+vIjtzOjE6IiciO3M6Mzoi772AIjtzOjE6IiciO3M6MjoiwrQiO3M6MToiJyI7czoyOiLOhCI7czoxOiInIjtzOjM6IuG/vSI7czoxOiInIjtzOjM6IuG+vSI7czoxOiInIjtzOjM6IuG+vyI7czoxOiInIjtzOjM6IuG/viI7czoxOiInIjtzOjI6Isq5IjtzOjE6IiciO3M6MjoizbQiO3M6MToiJyI7czoyOiLLiCI7czoxOiInIjtzOjI6IsuKIjtzOjE6IiciO3M6Mjoiy4siO3M6MToiJyI7czoyOiLLtCI7czoxOiInIjtzOjI6Isq7IjtzOjE6IiciO3M6Mjoiyr0iO3M6MToiJyI7czoyOiLKvCI7czoxOiInIjtzOjI6Isq+IjtzOjE6IiciO3M6Mzoi6p6MIjtzOjE6IiciO3M6Mjoi15kiO3M6MToiJyI7czoyOiLftCI7czoxOiInIjtzOjI6It+1IjtzOjE6IiciO3M6Mzoi4ZGKIjtzOjE6IiciO3M6Mzoi4ZuMIjtzOjE6IiciO3M6NDoi8Ja9kSI7czoxOiInIjtzOjQ6IvCWvZIiO3M6MToiJyI7czozOiLvvLsiO3M6MToiKCI7czozOiLinagiO3M6MToiKCI7czozOiLinbIiO3M6MToiKCI7czozOiLjgJQiO3M6MToiKCI7czozOiLvtL4iO3M6MToiKCI7czozOiLvvL0iO3M6MToiKSI7czozOiLinakiO3M6MToiKSI7czozOiLinbMiO3M6MToiKSI7czozOiLjgJUiO3M6MToiKSI7czozOiLvtL8iO3M6MToiKSI7czozOiLinbQiO3M6MToieyI7czo0OiLwnYSUIjtzOjE6InsiO3M6Mzoi4p21IjtzOjE6In0iO3M6Mzoi4ri/IjtzOjE6IrYiO3M6Mzoi4oGOIjtzOjE6IioiO3M6Mjoi2a0iO3M6MToiKiI7czozOiLiiJciO3M6MToiKiI7czo0OiLwkIyfIjtzOjE6IioiO3M6Mzoi4Zy1IjtzOjE6Ii8iO3M6Mzoi4oGBIjtzOjE6Ii8iO3M6Mzoi4oiVIjtzOjE6Ii8iO3M6Mzoi4oGEIjtzOjE6Ii8iO3M6Mzoi4pWxIjtzOjE6Ii8iO3M6Mzoi4p+LIjtzOjE6Ii8iO3M6Mzoi4qe4IjtzOjE6Ii8iO3M6NDoi8J2IuiI7czoxOiIvIjtzOjM6IuOHkyI7czoxOiIvIjtzOjM6IuOAsyI7czoxOiIvIjtzOjM6IuKzhiI7czoxOiIvIjtzOjM6IuODjiI7czoxOiIvIjtzOjM6IuS4vyI7czoxOiIvIjtzOjM6IuK8gyI7czoxOiIvIjtzOjM6Iu+8vCI7czoxOiJcIjtzOjM6Iu+5qCI7czoxOiJcIjtzOjM6IuKIliI7czoxOiJcIjtzOjM6IuKfjSI7czoxOiJcIjtzOjM6IuKntSI7czoxOiJcIjtzOjM6IuKnuSI7czoxOiJcIjtzOjQ6IvCdiI8iO3M6MToiXCI7czo0OiLwnYi7IjtzOjE6IlwiO3M6Mzoi44eUIjtzOjE6IlwiO3M6Mzoi5Li2IjtzOjE6IlwiO3M6Mzoi4ryCIjtzOjE6IlwiO3M6Mzoi6p24IjtzOjE6IiYiO3M6Mjoiy4QiO3M6MToiXiI7czoyOiLLhiI7czoxOiJeIjtzOjM6IuK4sCI7czoxOiKwIjtzOjI6IsuaIjtzOjE6IrAiO3M6Mzoi4oiYIjtzOjE6IrAiO3M6Mzoi4peLIjtzOjE6IrAiO3M6Mzoi4pemIjtzOjE6IrAiO3M6Mzoi4pK4IjtzOjE6IqkiO3M6Mzoi4pOHIjtzOjE6Iq4iO3M6Mzoi4ZutIjtzOjE6IisiO3M6Mzoi4p6VIjtzOjE6IisiO3M6NDoi8JCKmyI7czoxOiIrIjtzOjM6IuKelyI7czoxOiL3IjtzOjM6IuKAuSI7czoxOiI8IjtzOjM6IuKdriI7czoxOiI8IjtzOjI6IsuCIjtzOjE6IjwiO3M6NDoi8J2ItiI7czoxOiI8IjtzOjM6IuGQuCI7czoxOiI8IjtzOjM6IuGasiI7czoxOiI8IjtzOjM6IuGQgCI7czoxOiI9IjtzOjM6IuK5gCI7czoxOiI9IjtzOjM6IuOCoCI7czoxOiI9IjtzOjM6IuqTvyI7czoxOiI9IjtzOjM6IuKAuiI7czoxOiI+IjtzOjM6IuKdryI7czoxOiI+IjtzOjI6IsuDIjtzOjE6Ij4iO3M6NDoi8J2ItyI7czoxOiI+IjtzOjM6IuGQsyI7czoxOiI+IjtzOjQ6IvCWvL8iO3M6MToiPiI7czozOiLigZMiO3M6MToifiI7czoyOiLLnCI7czoxOiJ+IjtzOjM6IuG/gCI7czoxOiJ+IjtzOjM6IuKIvCI7czoxOiJ+IjtzOjM6IuKCpCI7czoxOiKjIjtzOjQ6IvCdn5AiO3M6MToiMiI7czo0OiLwnZ+aIjtzOjE6IjIiO3M6NDoi8J2fpCI7czoxOiIyIjtzOjQ6IvCdn64iO3M6MToiMiI7czo0OiLwnZ+4IjtzOjE6IjIiO3M6Mzoi6p2aIjtzOjE6IjIiO3M6MjoixqciO3M6MToiMiI7czoyOiLPqCI7czoxOiIyIjtzOjM6IuqZhCI7czoxOiIyIjtzOjM6IuGSvyI7czoxOiIyIjtzOjM6IuqbryI7czoxOiIyIjtzOjQ6IvCdiIYiO3M6MToiMyI7czo0OiLwnZ+RIjtzOjE6IjMiO3M6NDoi8J2fmyI7czoxOiIzIjtzOjQ6IvCdn6UiO3M6MToiMyI7czo0OiLwnZ+vIjtzOjE6IjMiO3M6NDoi8J2fuSI7czoxOiIzIjtzOjM6IuqeqyI7czoxOiIzIjtzOjI6IsicIjtzOjE6IjMiO3M6MjoixrciO3M6MToiMyI7czozOiLqnaoiO3M6MToiMyI7czozOiLis4wiO3M6MToiMyI7czoyOiLQlyI7czoxOiIzIjtzOjI6ItOgIjtzOjE6IjMiO3M6NDoi8Ja8uyI7czoxOiIzIjtzOjQ6IvCRo4oiO3M6MToiMyI7czo0OiLwnZ+SIjtzOjE6IjQiO3M6NDoi8J2fnCI7czoxOiI0IjtzOjQ6IvCdn6YiO3M6MToiNCI7czo0OiLwnZ+wIjtzOjE6IjQiO3M6NDoi8J2fuiI7czoxOiI0IjtzOjM6IuGPjiI7czoxOiI0IjtzOjQ6IvCRoq8iO3M6MToiNCI7czo0OiLwnZ+TIjtzOjE6IjUiO3M6NDoi8J2fnSI7czoxOiI1IjtzOjQ6IvCdn6ciO3M6MToiNSI7czo0OiLwnZ+xIjtzOjE6IjUiO3M6NDoi8J2fuyI7czoxOiI1IjtzOjI6Isa8IjtzOjE6IjUiO3M6NDoi8JGiuyI7czoxOiI1IjtzOjQ6IvCdn5QiO3M6MToiNiI7czo0OiLwnZ+eIjtzOjE6IjYiO3M6NDoi8J2fqCI7czoxOiI2IjtzOjQ6IvCdn7IiO3M6MToiNiI7czo0OiLwnZ+8IjtzOjE6IjYiO3M6Mzoi4rOSIjtzOjE6IjYiO3M6Mjoi0LEiO3M6MToiNiI7czozOiLhj64iO3M6MToiNiI7czo0OiLwkaOVIjtzOjE6IjYiO3M6NDoi8J2IkiI7czoxOiI3IjtzOjQ6IvCdn5UiO3M6MToiNyI7czo0OiLwnZ+fIjtzOjE6IjciO3M6NDoi8J2fqSI7czoxOiI3IjtzOjQ6IvCdn7MiO3M6MToiNyI7czo0OiLwnZ+9IjtzOjE6IjciO3M6NDoi8JCTkiI7czoxOiI3IjtzOjQ6IvCRo4YiO3M6MToiNyI7czozOiLgrIMiO3M6MToiOCI7czozOiLgp6oiO3M6MToiOCI7czozOiLgqaoiO3M6MToiOCI7czo0OiLwnqOLIjtzOjE6IjgiO3M6NDoi8J2fliI7czoxOiI4IjtzOjQ6IvCdn6AiO3M6MToiOCI7czo0OiLwnZ+qIjtzOjE6IjgiO3M6NDoi8J2ftCI7czoxOiI4IjtzOjQ6IvCdn74iO3M6MToiOCI7czoyOiLIoyI7czoxOiI4IjtzOjI6IsiiIjtzOjE6IjgiO3M6NDoi8JCMmiI7czoxOiI4IjtzOjM6IuCppyI7czoxOiI5IjtzOjM6IuCtqCI7czoxOiI5IjtzOjM6IuCnrSI7czoxOiI5IjtzOjM6IuC1rSI7czoxOiI5IjtzOjQ6IvCdn5ciO3M6MToiOSI7czo0OiLwnZ+hIjtzOjE6IjkiO3M6NDoi8J2fqyI7czoxOiI5IjtzOjQ6IvCdn7UiO3M6MToiOSI7czo0OiLwnZ+/IjtzOjE6IjkiO3M6Mzoi6p2uIjtzOjE6IjkiO3M6Mzoi4rOKIjtzOjE6IjkiO3M6NDoi8JGjjCI7czoxOiI5IjtzOjQ6IvCRoqwiO3M6MToiOSI7czo0OiLwkaOWIjtzOjE6IjkiO3M6Mzoi4o26IjtzOjE6ImEiO3M6Mzoi772BIjtzOjE6ImEiO3M6NDoi8J2QmiI7czoxOiJhIjtzOjQ6IvCdkY4iO3M6MToiYSI7czo0OiLwnZKCIjtzOjE6ImEiO3M6NDoi8J2StiI7czoxOiJhIjtzOjQ6IvCdk6oiO3M6MToiYSI7czo0OiLwnZSeIjtzOjE6ImEiO3M6NDoi8J2VkiI7czoxOiJhIjtzOjQ6IvCdloYiO3M6MToiYSI7czo0OiLwnZa6IjtzOjE6ImEiO3M6NDoi8J2XriI7czoxOiJhIjtzOjQ6IvCdmKIiO3M6MToiYSI7czo0OiLwnZmWIjtzOjE6ImEiO3M6NDoi8J2aiiI7czoxOiJhIjtzOjI6IsmRIjtzOjE6ImEiO3M6MjoizrEiO3M6MToiYSI7czo0OiLwnZuCIjtzOjE6ImEiO3M6NDoi8J2bvCI7czoxOiJhIjtzOjQ6IvCdnLYiO3M6MToiYSI7czo0OiLwnZ2wIjtzOjE6ImEiO3M6NDoi8J2eqiI7czoxOiJhIjtzOjI6ItCwIjtzOjE6ImEiO3M6Mzoi77yhIjtzOjE6IkEiO3M6NDoi8J2QgCI7czoxOiJBIjtzOjQ6IvCdkLQiO3M6MToiQSI7czo0OiLwnZGoIjtzOjE6IkEiO3M6NDoi8J2SnCI7czoxOiJBIjtzOjQ6IvCdk5AiO3M6MToiQSI7czo0OiLwnZSEIjtzOjE6IkEiO3M6NDoi8J2UuCI7czoxOiJBIjtzOjQ6IvCdlawiO3M6MToiQSI7czo0OiLwnZagIjtzOjE6IkEiO3M6NDoi8J2XlCI7czoxOiJBIjtzOjQ6IvCdmIgiO3M6MToiQSI7czo0OiLwnZi8IjtzOjE6IkEiO3M6NDoi8J2ZsCI7czoxOiJBIjtzOjI6Is6RIjtzOjE6IkEiO3M6NDoi8J2aqCI7czoxOiJBIjtzOjQ6IvCdm6IiO3M6MToiQSI7czo0OiLwnZycIjtzOjE6IkEiO3M6NDoi8J2dliI7czoxOiJBIjtzOjQ6IvCdnpAiO3M6MToiQSI7czoyOiLQkCI7czoxOiJBIjtzOjM6IuGOqiI7czoxOiJBIjtzOjM6IuGXhSI7czoxOiJBIjtzOjM6IuqTriI7czoxOiJBIjtzOjQ6IvCWvYAiO3M6MToiQSI7czo0OiLwkIqgIjtzOjE6IkEiO3M6MjoiyKciO3M6MToi5SI7czoyOiLIpiI7czoxOiLFIjtzOjQ6IvCdkJsiO3M6MToiYiI7czo0OiLwnZGPIjtzOjE6ImIiO3M6NDoi8J2SgyI7czoxOiJiIjtzOjQ6IvCdkrciO3M6MToiYiI7czo0OiLwnZOrIjtzOjE6ImIiO3M6NDoi8J2UnyI7czoxOiJiIjtzOjQ6IvCdlZMiO3M6MToiYiI7czo0OiLwnZaHIjtzOjE6ImIiO3M6NDoi8J2WuyI7czoxOiJiIjtzOjQ6IvCdl68iO3M6MToiYiI7czo0OiLwnZijIjtzOjE6ImIiO3M6NDoi8J2ZlyI7czoxOiJiIjtzOjQ6IvCdmosiO3M6MToiYiI7czoyOiLGhCI7czoxOiJiIjtzOjI6ItCsIjtzOjE6ImIiO3M6Mzoi4Y+PIjtzOjE6ImIiO3M6Mzoi4ZGyIjtzOjE6ImIiO3M6Mzoi4ZavIjtzOjE6ImIiO3M6Mzoi77yiIjtzOjE6IkIiO3M6Mzoi4oSsIjtzOjE6IkIiO3M6NDoi8J2QgSI7czoxOiJCIjtzOjQ6IvCdkLUiO3M6MToiQiI7czo0OiLwnZGpIjtzOjE6IkIiO3M6NDoi8J2TkSI7czoxOiJCIjtzOjQ6IvCdlIUiO3M6MToiQiI7czo0OiLwnZS5IjtzOjE6IkIiO3M6NDoi8J2VrSI7czoxOiJCIjtzOjQ6IvCdlqEiO3M6MToiQiI7czo0OiLwnZeVIjtzOjE6IkIiO3M6NDoi8J2YiSI7czoxOiJCIjtzOjQ6IvCdmL0iO3M6MToiQiI7czo0OiLwnZmxIjtzOjE6IkIiO3M6Mzoi6p60IjtzOjE6IkIiO3M6MjoizpIiO3M6MToiQiI7czo0OiLwnZqpIjtzOjE6IkIiO3M6NDoi8J2boyI7czoxOiJCIjtzOjQ6IvCdnJ0iO3M6MToiQiI7czo0OiLwnZ2XIjtzOjE6IkIiO3M6NDoi8J2ekSI7czoxOiJCIjtzOjI6ItCSIjtzOjE6IkIiO3M6Mzoi4Y+0IjtzOjE6IkIiO3M6Mzoi4Ze3IjtzOjE6IkIiO3M6Mzoi6pOQIjtzOjE6IkIiO3M6NDoi8JCKgiI7czoxOiJCIjtzOjQ6IvCQiqEiO3M6MToiQiI7czo0OiLwkIyBIjtzOjE6IkIiO3M6Mzoi772DIjtzOjE6ImMiO3M6Mzoi4oW9IjtzOjE6ImMiO3M6NDoi8J2QnCI7czoxOiJjIjtzOjQ6IvCdkZAiO3M6MToiYyI7czo0OiLwnZKEIjtzOjE6ImMiO3M6NDoi8J2SuCI7czoxOiJjIjtzOjQ6IvCdk6wiO3M6MToiYyI7czo0OiLwnZSgIjtzOjE6ImMiO3M6NDoi8J2VlCI7czoxOiJjIjtzOjQ6IvCdlogiO3M6MToiYyI7czo0OiLwnZa8IjtzOjE6ImMiO3M6NDoi8J2XsCI7czoxOiJjIjtzOjQ6IvCdmKQiO3M6MToiYyI7czo0OiLwnZmYIjtzOjE6ImMiO3M6NDoi8J2ajCI7czoxOiJjIjtzOjM6IuG0hCI7czoxOiJjIjtzOjI6Is+yIjtzOjE6ImMiO3M6Mzoi4rKlIjtzOjE6ImMiO3M6Mjoi0YEiO3M6MToiYyI7czozOiLqrq8iO3M6MToiYyI7czo0OiLwkJC9IjtzOjE6ImMiO3M6NDoi8J+djCI7czoxOiJDIjtzOjQ6IvCRo7IiO3M6MToiQyI7czo0OiLwkaOpIjtzOjE6IkMiO3M6Mzoi77yjIjtzOjE6IkMiO3M6Mzoi4oWtIjtzOjE6IkMiO3M6Mzoi4oSCIjtzOjE6IkMiO3M6Mzoi4oStIjtzOjE6IkMiO3M6NDoi8J2QgiI7czoxOiJDIjtzOjQ6IvCdkLYiO3M6MToiQyI7czo0OiLwnZGqIjtzOjE6IkMiO3M6NDoi8J2SniI7czoxOiJDIjtzOjQ6IvCdk5IiO3M6MToiQyI7czo0OiLwnZWuIjtzOjE6IkMiO3M6NDoi8J2WoiI7czoxOiJDIjtzOjQ6IvCdl5YiO3M6MToiQyI7czo0OiLwnZiKIjtzOjE6IkMiO3M6NDoi8J2YviI7czoxOiJDIjtzOjQ6IvCdmbIiO3M6MToiQyI7czoyOiLPuSI7czoxOiJDIjtzOjM6IuKypCI7czoxOiJDIjtzOjI6ItChIjtzOjE6IkMiO3M6Mzoi4Y+fIjtzOjE6IkMiO3M6Mzoi6pOaIjtzOjE6IkMiO3M6NDoi8JCKoiI7czoxOiJDIjtzOjQ6IvCQjIIiO3M6MToiQyI7czo0OiLwkJCVIjtzOjE6IkMiO3M6NDoi8JCUnCI7czoxOiJDIjtzOjM6IuKFviI7czoxOiJkIjtzOjM6IuKFhiI7czoxOiJkIjtzOjQ6IvCdkJ0iO3M6MToiZCI7czo0OiLwnZGRIjtzOjE6ImQiO3M6NDoi8J2ShSI7czoxOiJkIjtzOjQ6IvCdkrkiO3M6MToiZCI7czo0OiLwnZOtIjtzOjE6ImQiO3M6NDoi8J2UoSI7czoxOiJkIjtzOjQ6IvCdlZUiO3M6MToiZCI7czo0OiLwnZaJIjtzOjE6ImQiO3M6NDoi8J2WvSI7czoxOiJkIjtzOjQ6IvCdl7EiO3M6MToiZCI7czo0OiLwnZilIjtzOjE6ImQiO3M6NDoi8J2ZmSI7czoxOiJkIjtzOjQ6IvCdmo0iO3M6MToiZCI7czoyOiLUgSI7czoxOiJkIjtzOjM6IuGPpyI7czoxOiJkIjtzOjM6IuGRryI7czoxOiJkIjtzOjM6IuqTkiI7czoxOiJkIjtzOjM6IuKFriI7czoxOiJEIjtzOjM6IuKFhSI7czoxOiJEIjtzOjQ6IvCdkIMiO3M6MToiRCI7czo0OiLwnZC3IjtzOjE6IkQiO3M6NDoi8J2RqyI7czoxOiJEIjtzOjQ6IvCdkp8iO3M6MToiRCI7czo0OiLwnZOTIjtzOjE6IkQiO3M6NDoi8J2UhyI7czoxOiJEIjtzOjQ6IvCdlLsiO3M6MToiRCI7czo0OiLwnZWvIjtzOjE6IkQiO3M6NDoi8J2WoyI7czoxOiJEIjtzOjQ6IvCdl5ciO3M6MToiRCI7czo0OiLwnZiLIjtzOjE6IkQiO3M6NDoi8J2YvyI7czoxOiJEIjtzOjQ6IvCdmbMiO3M6MToiRCI7czozOiLhjqAiO3M6MToiRCI7czozOiLhl54iO3M6MToiRCI7czozOiLhl6oiO3M6MToiRCI7czozOiLqk5MiO3M6MToiRCI7czozOiLihK4iO3M6MToiZSI7czozOiLvvYUiO3M6MToiZSI7czozOiLihK8iO3M6MToiZSI7czozOiLihYciO3M6MToiZSI7czo0OiLwnZCeIjtzOjE6ImUiO3M6NDoi8J2RkiI7czoxOiJlIjtzOjQ6IvCdkoYiO3M6MToiZSI7czo0OiLwnZOuIjtzOjE6ImUiO3M6NDoi8J2UoiI7czoxOiJlIjtzOjQ6IvCdlZYiO3M6MToiZSI7czo0OiLwnZaKIjtzOjE6ImUiO3M6NDoi8J2WviI7czoxOiJlIjtzOjQ6IvCdl7IiO3M6MToiZSI7czo0OiLwnZimIjtzOjE6ImUiO3M6NDoi8J2ZmiI7czoxOiJlIjtzOjQ6IvCdmo4iO3M6MToiZSI7czozOiLqrLIiO3M6MToiZSI7czoyOiLQtSI7czoxOiJlIjtzOjI6ItK9IjtzOjE6ImUiO3M6Mjoiw6kiO3M6MToiZSI7czozOiLii78iO3M6MToiRSI7czozOiLvvKUiO3M6MToiRSI7czozOiLihLAiO3M6MToiRSI7czo0OiLwnZCEIjtzOjE6IkUiO3M6NDoi8J2QuCI7czoxOiJFIjtzOjQ6IvCdkawiO3M6MToiRSI7czo0OiLwnZOUIjtzOjE6IkUiO3M6NDoi8J2UiCI7czoxOiJFIjtzOjQ6IvCdlLwiO3M6MToiRSI7czo0OiLwnZWwIjtzOjE6IkUiO3M6NDoi8J2WpCI7czoxOiJFIjtzOjQ6IvCdl5giO3M6MToiRSI7czo0OiLwnZiMIjtzOjE6IkUiO3M6NDoi8J2ZgCI7czoxOiJFIjtzOjQ6IvCdmbQiO3M6MToiRSI7czoyOiLOlSI7czoxOiJFIjtzOjQ6IvCdmqwiO3M6MToiRSI7czo0OiLwnZumIjtzOjE6IkUiO3M6NDoi8J2coCI7czoxOiJFIjtzOjQ6IvCdnZoiO3M6MToiRSI7czo0OiLwnZ6UIjtzOjE6IkUiO3M6Mjoi0JUiO3M6MToiRSI7czozOiLitLkiO3M6MToiRSI7czozOiLhjqwiO3M6MToiRSI7czozOiLqk7AiO3M6MToiRSI7czo0OiLwkaKmIjtzOjE6IkUiO3M6NDoi8JGiriI7czoxOiJFIjtzOjQ6IvCQioYiO3M6MToiRSI7czo0OiLwnZCfIjtzOjE6ImYiO3M6NDoi8J2RkyI7czoxOiJmIjtzOjQ6IvCdkociO3M6MToiZiI7czo0OiLwnZK7IjtzOjE6ImYiO3M6NDoi8J2TryI7czoxOiJmIjtzOjQ6IvCdlKMiO3M6MToiZiI7czo0OiLwnZWXIjtzOjE6ImYiO3M6NDoi8J2WiyI7czoxOiJmIjtzOjQ6IvCdlr8iO3M6MToiZiI7czo0OiLwnZezIjtzOjE6ImYiO3M6NDoi8J2YpyI7czoxOiJmIjtzOjQ6IvCdmZsiO3M6MToiZiI7czo0OiLwnZqPIjtzOjE6ImYiO3M6Mzoi6qy1IjtzOjE6ImYiO3M6Mzoi6p6ZIjtzOjE6ImYiO3M6Mjoixb8iO3M6MToiZiI7czozOiLhup0iO3M6MToiZiI7czoyOiLWhCI7czoxOiJmIjtzOjQ6IvCdiJMiO3M6MToiRiI7czozOiLihLEiO3M6MToiRiI7czo0OiLwnZCFIjtzOjE6IkYiO3M6NDoi8J2QuSI7czoxOiJGIjtzOjQ6IvCdka0iO3M6MToiRiI7czo0OiLwnZOVIjtzOjE6IkYiO3M6NDoi8J2UiSI7czoxOiJGIjtzOjQ6IvCdlL0iO3M6MToiRiI7czo0OiLwnZWxIjtzOjE6IkYiO3M6NDoi8J2WpSI7czoxOiJGIjtzOjQ6IvCdl5kiO3M6MToiRiI7czo0OiLwnZiNIjtzOjE6IkYiO3M6NDoi8J2ZgSI7czoxOiJGIjtzOjQ6IvCdmbUiO3M6MToiRiI7czozOiLqnpgiO3M6MToiRiI7czoyOiLPnCI7czoxOiJGIjtzOjQ6IvCdn4oiO3M6MToiRiI7czozOiLhlrQiO3M6MToiRiI7czozOiLqk50iO3M6MToiRiI7czo0OiLwkaOCIjtzOjE6IkYiO3M6NDoi8JGioiI7czoxOiJGIjtzOjQ6IvCQiociO3M6MToiRiI7czo0OiLwkIqlIjtzOjE6IkYiO3M6NDoi8JCUpSI7czoxOiJGIjtzOjM6Iu+9hyI7czoxOiJnIjtzOjM6IuKEiiI7czoxOiJnIjtzOjQ6IvCdkKAiO3M6MToiZyI7czo0OiLwnZGUIjtzOjE6ImciO3M6NDoi8J2SiCI7czoxOiJnIjtzOjQ6IvCdk7AiO3M6MToiZyI7czo0OiLwnZSkIjtzOjE6ImciO3M6NDoi8J2VmCI7czoxOiJnIjtzOjQ6IvCdlowiO3M6MToiZyI7czo0OiLwnZeAIjtzOjE6ImciO3M6NDoi8J2XtCI7czoxOiJnIjtzOjQ6IvCdmKgiO3M6MToiZyI7czo0OiLwnZmcIjtzOjE6ImciO3M6NDoi8J2akCI7czoxOiJnIjtzOjI6IsmhIjtzOjE6ImciO3M6Mzoi4baDIjtzOjE6ImciO3M6Mjoixo0iO3M6MToiZyI7czoyOiLWgSI7czoxOiJnIjtzOjQ6IvCdkIYiO3M6MToiRyI7czo0OiLwnZC6IjtzOjE6IkciO3M6NDoi8J2RriI7czoxOiJHIjtzOjQ6IvCdkqIiO3M6MToiRyI7czo0OiLwnZOWIjtzOjE6IkciO3M6NDoi8J2UiiI7czoxOiJHIjtzOjQ6IvCdlL4iO3M6MToiRyI7czo0OiLwnZWyIjtzOjE6IkciO3M6NDoi8J2WpiI7czoxOiJHIjtzOjQ6IvCdl5oiO3M6MToiRyI7czo0OiLwnZiOIjtzOjE6IkciO3M6NDoi8J2ZgiI7czoxOiJHIjtzOjQ6IvCdmbYiO3M6MToiRyI7czoyOiLUjCI7czoxOiJHIjtzOjM6IuGPgCI7czoxOiJHIjtzOjM6IuGPsyI7czoxOiJHIjtzOjM6IuqTliI7czoxOiJHIjtzOjM6Iu+9iCI7czoxOiJoIjtzOjM6IuKEjiI7czoxOiJoIjtzOjQ6IvCdkKEiO3M6MToiaCI7czo0OiLwnZKJIjtzOjE6ImgiO3M6NDoi8J2SvSI7czoxOiJoIjtzOjQ6IvCdk7EiO3M6MToiaCI7czo0OiLwnZSlIjtzOjE6ImgiO3M6NDoi8J2VmSI7czoxOiJoIjtzOjQ6IvCdlo0iO3M6MToiaCI7czo0OiLwnZeBIjtzOjE6ImgiO3M6NDoi8J2XtSI7czoxOiJoIjtzOjQ6IvCdmKkiO3M6MToiaCI7czo0OiLwnZmdIjtzOjE6ImgiO3M6NDoi8J2akSI7czoxOiJoIjtzOjI6ItK7IjtzOjE6ImgiO3M6Mjoi1bAiO3M6MToiaCI7czozOiLhj4IiO3M6MToiaCI7czozOiLvvKgiO3M6MToiSCI7czozOiLihIsiO3M6MToiSCI7czozOiLihIwiO3M6MToiSCI7czozOiLihI0iO3M6MToiSCI7czo0OiLwnZCHIjtzOjE6IkgiO3M6NDoi8J2QuyI7czoxOiJIIjtzOjQ6IvCdka8iO3M6MToiSCI7czo0OiLwnZOXIjtzOjE6IkgiO3M6NDoi8J2VsyI7czoxOiJIIjtzOjQ6IvCdlqciO3M6MToiSCI7czo0OiLwnZebIjtzOjE6IkgiO3M6NDoi8J2YjyI7czoxOiJIIjtzOjQ6IvCdmYMiO3M6MToiSCI7czo0OiLwnZm3IjtzOjE6IkgiO3M6MjoizpciO3M6MToiSCI7czo0OiLwnZquIjtzOjE6IkgiO3M6NDoi8J2bqCI7czoxOiJIIjtzOjQ6IvCdnKIiO3M6MToiSCI7czo0OiLwnZ2cIjtzOjE6IkgiO3M6NDoi8J2eliI7czoxOiJIIjtzOjM6IuKyjiI7czoxOiJIIjtzOjI6ItCdIjtzOjE6IkgiO3M6Mzoi4Y67IjtzOjE6IkgiO3M6Mzoi4ZW8IjtzOjE6IkgiO3M6Mzoi6pOnIjtzOjE6IkgiO3M6NDoi8JCLjyI7czoxOiJIIjtzOjI6IsubIjtzOjE6ImkiO3M6Mzoi4o2zIjtzOjE6ImkiO3M6Mzoi772JIjtzOjE6ImkiO3M6Mzoi4oWwIjtzOjE6ImkiO3M6Mzoi4oS5IjtzOjE6ImkiO3M6Mzoi4oWIIjtzOjE6ImkiO3M6NDoi8J2QoiI7czoxOiJpIjtzOjQ6IvCdkZYiO3M6MToiaSI7czo0OiLwnZKKIjtzOjE6ImkiO3M6NDoi8J2SviI7czoxOiJpIjtzOjQ6IvCdk7IiO3M6MToiaSI7czo0OiLwnZSmIjtzOjE6ImkiO3M6NDoi8J2VmiI7czoxOiJpIjtzOjQ6IvCdlo4iO3M6MToiaSI7czo0OiLwnZeCIjtzOjE6ImkiO3M6NDoi8J2XtiI7czoxOiJpIjtzOjQ6IvCdmKoiO3M6MToiaSI7czo0OiLwnZmeIjtzOjE6ImkiO3M6NDoi8J2akiI7czoxOiJpIjtzOjI6IsSxIjtzOjE6ImkiO3M6NDoi8J2apCI7czoxOiJpIjtzOjI6IsmqIjtzOjE6ImkiO3M6MjoiyakiO3M6MToiaSI7czoyOiLOuSI7czoxOiJpIjtzOjM6IuG+viI7czoxOiJpIjtzOjI6Is26IjtzOjE6ImkiO3M6NDoi8J2biiI7czoxOiJpIjtzOjQ6IvCdnIQiO3M6MToiaSI7czo0OiLwnZy+IjtzOjE6ImkiO3M6NDoi8J2duCI7czoxOiJpIjtzOjQ6IvCdnrIiO3M6MToiaSI7czoyOiLRliI7czoxOiJpIjtzOjM6IuqZhyI7czoxOiJpIjtzOjI6ItOPIjtzOjE6ImkiO3M6Mzoi6q21IjtzOjE6ImkiO3M6Mzoi4Y6lIjtzOjE6ImkiO3M6NDoi8JGjgyI7czoxOiJpIjtzOjI6IsOtIjtzOjE6ImkiO3M6Mzoi772KIjtzOjE6ImoiO3M6Mzoi4oWJIjtzOjE6ImoiO3M6NDoi8J2QoyI7czoxOiJqIjtzOjQ6IvCdkZciO3M6MToiaiI7czo0OiLwnZKLIjtzOjE6ImoiO3M6NDoi8J2SvyI7czoxOiJqIjtzOjQ6IvCdk7MiO3M6MToiaiI7czo0OiLwnZSnIjtzOjE6ImoiO3M6NDoi8J2VmyI7czoxOiJqIjtzOjQ6IvCdlo8iO3M6MToiaiI7czo0OiLwnZeDIjtzOjE6ImoiO3M6NDoi8J2XtyI7czoxOiJqIjtzOjQ6IvCdmKsiO3M6MToiaiI7czo0OiLwnZmfIjtzOjE6ImoiO3M6NDoi8J2akyI7czoxOiJqIjtzOjI6Is+zIjtzOjE6ImoiO3M6Mjoi0ZgiO3M6MToiaiI7czozOiLvvKoiO3M6MToiSiI7czo0OiLwnZCJIjtzOjE6IkoiO3M6NDoi8J2QvSI7czoxOiJKIjtzOjQ6IvCdkbEiO3M6MToiSiI7czo0OiLwnZKlIjtzOjE6IkoiO3M6NDoi8J2TmSI7czoxOiJKIjtzOjQ6IvCdlI0iO3M6MToiSiI7czo0OiLwnZWBIjtzOjE6IkoiO3M6NDoi8J2VtSI7czoxOiJKIjtzOjQ6IvCdlqkiO3M6MToiSiI7czo0OiLwnZedIjtzOjE6IkoiO3M6NDoi8J2YkSI7czoxOiJKIjtzOjQ6IvCdmYUiO3M6MToiSiI7czo0OiLwnZm5IjtzOjE6IkoiO3M6Mzoi6p6yIjtzOjE6IkoiO3M6Mjoizb8iO3M6MToiSiI7czoyOiLQiCI7czoxOiJKIjtzOjM6IuGOqyI7czoxOiJKIjtzOjM6IuGSjSI7czoxOiJKIjtzOjM6IuqTmSI7czoxOiJKIjtzOjQ6IvCdkKQiO3M6MToiayI7czo0OiLwnZGYIjtzOjE6ImsiO3M6NDoi8J2SjCI7czoxOiJrIjtzOjQ6IvCdk4AiO3M6MToiayI7czo0OiLwnZO0IjtzOjE6ImsiO3M6NDoi8J2UqCI7czoxOiJrIjtzOjQ6IvCdlZwiO3M6MToiayI7czo0OiLwnZaQIjtzOjE6ImsiO3M6NDoi8J2XhCI7czoxOiJrIjtzOjQ6IvCdl7giO3M6MToiayI7czo0OiLwnZisIjtzOjE6ImsiO3M6NDoi8J2ZoCI7czoxOiJrIjtzOjQ6IvCdmpQiO3M6MToiayI7czozOiLihKoiO3M6MToiSyI7czozOiLvvKsiO3M6MToiSyI7czo0OiLwnZCKIjtzOjE6IksiO3M6NDoi8J2QviI7czoxOiJLIjtzOjQ6IvCdkbIiO3M6MToiSyI7czo0OiLwnZKmIjtzOjE6IksiO3M6NDoi8J2TmiI7czoxOiJLIjtzOjQ6IvCdlI4iO3M6MToiSyI7czo0OiLwnZWCIjtzOjE6IksiO3M6NDoi8J2VtiI7czoxOiJLIjtzOjQ6IvCdlqoiO3M6MToiSyI7czo0OiLwnZeeIjtzOjE6IksiO3M6NDoi8J2YkiI7czoxOiJLIjtzOjQ6IvCdmYYiO3M6MToiSyI7czo0OiLwnZm6IjtzOjE6IksiO3M6MjoizpoiO3M6MToiSyI7czo0OiLwnZqxIjtzOjE6IksiO3M6NDoi8J2bqyI7czoxOiJLIjtzOjQ6IvCdnKUiO3M6MToiSyI7czo0OiLwnZ2fIjtzOjE6IksiO3M6NDoi8J2emSI7czoxOiJLIjtzOjM6IuKylCI7czoxOiJLIjtzOjI6ItCaIjtzOjE6IksiO3M6Mzoi4Y+mIjtzOjE6IksiO3M6Mzoi4ZuVIjtzOjE6IksiO3M6Mzoi6pOXIjtzOjE6IksiO3M6NDoi8JCUmCI7czoxOiJLIjtzOjI6IteAIjtzOjE6ImwiO3M6Mzoi4oijIjtzOjE6ImwiO3M6Mzoi4o+9IjtzOjE6ImwiO3M6Mzoi77+oIjtzOjE6ImwiO2k6MTtzOjE6ImwiO3M6Mjoi2aEiO3M6MToibCI7czoyOiLbsSI7czoxOiJsIjtzOjQ6IvCQjKAiO3M6MToibCI7czo0OiLwnqOHIjtzOjE6ImwiO3M6NDoi8J2fjyI7czoxOiJsIjtzOjQ6IvCdn5kiO3M6MToibCI7czo0OiLwnZ+jIjtzOjE6ImwiO3M6NDoi8J2frSI7czoxOiJsIjtzOjQ6IvCdn7ciO3M6MToibCI7czozOiLvvKkiO3M6MToibCI7czozOiLihaAiO3M6MToibCI7czozOiLihJAiO3M6MToibCI7czozOiLihJEiO3M6MToibCI7czo0OiLwnZCIIjtzOjE6ImwiO3M6NDoi8J2QvCI7czoxOiJsIjtzOjQ6IvCdkbAiO3M6MToibCI7czo0OiLwnZOYIjtzOjE6ImwiO3M6NDoi8J2VgCI7czoxOiJsIjtzOjQ6IvCdlbQiO3M6MToibCI7czo0OiLwnZaoIjtzOjE6ImwiO3M6NDoi8J2XnCI7czoxOiJsIjtzOjQ6IvCdmJAiO3M6MToibCI7czo0OiLwnZmEIjtzOjE6ImwiO3M6NDoi8J2ZuCI7czoxOiJsIjtzOjI6IsaWIjtzOjE6ImwiO3M6Mzoi772MIjtzOjE6ImwiO3M6Mzoi4oW8IjtzOjE6ImwiO3M6Mzoi4oSTIjtzOjE6ImwiO3M6NDoi8J2QpSI7czoxOiJsIjtzOjQ6IvCdkZkiO3M6MToibCI7czo0OiLwnZKNIjtzOjE6ImwiO3M6NDoi8J2TgSI7czoxOiJsIjtzOjQ6IvCdk7UiO3M6MToibCI7czo0OiLwnZSpIjtzOjE6ImwiO3M6NDoi8J2VnSI7czoxOiJsIjtzOjQ6IvCdlpEiO3M6MToibCI7czo0OiLwnZeFIjtzOjE6ImwiO3M6NDoi8J2XuSI7czoxOiJsIjtzOjQ6IvCdmK0iO3M6MToibCI7czo0OiLwnZmhIjtzOjE6ImwiO3M6NDoi8J2alSI7czoxOiJsIjtzOjI6IseAIjtzOjE6ImwiO3M6MjoizpkiO3M6MToibCI7czo0OiLwnZqwIjtzOjE6ImwiO3M6NDoi8J2bqiI7czoxOiJsIjtzOjQ6IvCdnKQiO3M6MToibCI7czo0OiLwnZ2eIjtzOjE6ImwiO3M6NDoi8J2emCI7czoxOiJsIjtzOjM6IuKykiI7czoxOiJsIjtzOjI6ItCGIjtzOjE6ImwiO3M6Mjoi04AiO3M6MToibCI7czoyOiLXlSI7czoxOiJsIjtzOjI6ItefIjtzOjE6ImwiO3M6Mjoi2KciO3M6MToibCI7czo0OiLwnriAIjtzOjE6ImwiO3M6NDoi8J66gCI7czoxOiJsIjtzOjM6Iu+6jiI7czoxOiJsIjtzOjM6Iu+6jSI7czoxOiJsIjtzOjI6It+KIjtzOjE6ImwiO3M6Mzoi4rWPIjtzOjE6ImwiO3M6Mzoi4ZuBIjtzOjE6ImwiO3M6Mzoi6pOyIjtzOjE6ImwiO3M6NDoi8Ja8qCI7czoxOiJsIjtzOjQ6IvCQiooiO3M6MToibCI7czo0OiLwkIyJIjtzOjE6ImwiO3M6NDoi8J2IqiI7czoxOiJMIjtzOjM6IuKFrCI7czoxOiJMIjtzOjM6IuKEkiI7czoxOiJMIjtzOjQ6IvCdkIsiO3M6MToiTCI7czo0OiLwnZC/IjtzOjE6IkwiO3M6NDoi8J2RsyI7czoxOiJMIjtzOjQ6IvCdk5siO3M6MToiTCI7czo0OiLwnZSPIjtzOjE6IkwiO3M6NDoi8J2VgyI7czoxOiJMIjtzOjQ6IvCdlbciO3M6MToiTCI7czo0OiLwnZarIjtzOjE6IkwiO3M6NDoi8J2XnyI7czoxOiJMIjtzOjQ6IvCdmJMiO3M6MToiTCI7czo0OiLwnZmHIjtzOjE6IkwiO3M6NDoi8J2ZuyI7czoxOiJMIjtzOjM6IuKzkCI7czoxOiJMIjtzOjM6IuGPniI7czoxOiJMIjtzOjM6IuGSqiI7czoxOiJMIjtzOjM6IuqToSI7czoxOiJMIjtzOjQ6IvCWvJYiO3M6MToiTCI7czo0OiLwkaKjIjtzOjE6IkwiO3M6NDoi8JGisiI7czoxOiJMIjtzOjQ6IvCQkJsiO3M6MToiTCI7czo0OiLwkJSmIjtzOjE6IkwiO3M6Mzoi77ytIjtzOjE6Ik0iO3M6Mzoi4oWvIjtzOjE6Ik0iO3M6Mzoi4oSzIjtzOjE6Ik0iO3M6NDoi8J2QjCI7czoxOiJNIjtzOjQ6IvCdkYAiO3M6MToiTSI7czo0OiLwnZG0IjtzOjE6Ik0iO3M6NDoi8J2TnCI7czoxOiJNIjtzOjQ6IvCdlJAiO3M6MToiTSI7czo0OiLwnZWEIjtzOjE6Ik0iO3M6NDoi8J2VuCI7czoxOiJNIjtzOjQ6IvCdlqwiO3M6MToiTSI7czo0OiLwnZegIjtzOjE6Ik0iO3M6NDoi8J2YlCI7czoxOiJNIjtzOjQ6IvCdmYgiO3M6MToiTSI7czo0OiLwnZm8IjtzOjE6Ik0iO3M6MjoizpwiO3M6MToiTSI7czo0OiLwnZqzIjtzOjE6Ik0iO3M6NDoi8J2brSI7czoxOiJNIjtzOjQ6IvCdnKciO3M6MToiTSI7czo0OiLwnZ2hIjtzOjE6Ik0iO3M6NDoi8J2emyI7czoxOiJNIjtzOjI6Is+6IjtzOjE6Ik0iO3M6Mzoi4rKYIjtzOjE6Ik0iO3M6Mjoi0JwiO3M6MToiTSI7czozOiLhjrciO3M6MToiTSI7czozOiLhl7AiO3M6MToiTSI7czozOiLhm5YiO3M6MToiTSI7czozOiLqk58iO3M6MToiTSI7czo0OiLwkIqwIjtzOjE6Ik0iO3M6NDoi8JCMkSI7czoxOiJNIjtzOjQ6IvCdkKciO3M6MToibiI7czo0OiLwnZGbIjtzOjE6Im4iO3M6NDoi8J2SjyI7czoxOiJuIjtzOjQ6IvCdk4MiO3M6MToibiI7czo0OiLwnZO3IjtzOjE6Im4iO3M6NDoi8J2UqyI7czoxOiJuIjtzOjQ6IvCdlZ8iO3M6MToibiI7czo0OiLwnZaTIjtzOjE6Im4iO3M6NDoi8J2XhyI7czoxOiJuIjtzOjQ6IvCdl7siO3M6MToibiI7czo0OiLwnZivIjtzOjE6Im4iO3M6NDoi8J2ZoyI7czoxOiJuIjtzOjQ6IvCdmpciO3M6MToibiI7czoyOiLVuCI7czoxOiJuIjtzOjI6ItW8IjtzOjE6Im4iO3M6MjoiybQiO3M6MToibiI7czozOiLvvK4iO3M6MToiTiI7czozOiLihJUiO3M6MToiTiI7czo0OiLwnZCNIjtzOjE6Ik4iO3M6NDoi8J2RgSI7czoxOiJOIjtzOjQ6IvCdkbUiO3M6MToiTiI7czo0OiLwnZKpIjtzOjE6Ik4iO3M6NDoi8J2TnSI7czoxOiJOIjtzOjQ6IvCdlJEiO3M6MToiTiI7czo0OiLwnZW5IjtzOjE6Ik4iO3M6NDoi8J2WrSI7czoxOiJOIjtzOjQ6IvCdl6EiO3M6MToiTiI7czo0OiLwnZiVIjtzOjE6Ik4iO3M6NDoi8J2ZiSI7czoxOiJOIjtzOjQ6IvCdmb0iO3M6MToiTiI7czoyOiLOnSI7czoxOiJOIjtzOjQ6IvCdmrQiO3M6MToiTiI7czo0OiLwnZuuIjtzOjE6Ik4iO3M6NDoi8J2cqCI7czoxOiJOIjtzOjQ6IvCdnaIiO3M6MToiTiI7czo0OiLwnZ6cIjtzOjE6Ik4iO3M6Mzoi4rKaIjtzOjE6Ik4iO3M6Mzoi6pOgIjtzOjE6Ik4iO3M6NDoi8JCUkyI7czoxOiJOIjtzOjM6IuCwgiI7czoxOiJvIjtzOjM6IuCygiI7czoxOiJvIjtzOjM6IuC0giI7czoxOiJvIjtzOjM6IuC2giI7czoxOiJvIjtzOjM6IuClpiI7czoxOiJvIjtzOjM6IuCppiI7czoxOiJvIjtzOjM6IuCrpiI7czoxOiJvIjtzOjM6IuCvpiI7czoxOiJvIjtzOjM6IuCxpiI7czoxOiJvIjtzOjM6IuCzpiI7czoxOiJvIjtzOjM6IuC1piI7czoxOiJvIjtzOjM6IuC5kCI7czoxOiJvIjtzOjM6IuC7kCI7czoxOiJvIjtzOjM6IuGBgCI7czoxOiJvIjtzOjI6ItmlIjtzOjE6Im8iO3M6Mjoi27UiO3M6MToibyI7czozOiLvvY8iO3M6MToibyI7czozOiLihLQiO3M6MToibyI7czo0OiLwnZCoIjtzOjE6Im8iO3M6NDoi8J2RnCI7czoxOiJvIjtzOjQ6IvCdkpAiO3M6MToibyI7czo0OiLwnZO4IjtzOjE6Im8iO3M6NDoi8J2UrCI7czoxOiJvIjtzOjQ6IvCdlaAiO3M6MToibyI7czo0OiLwnZaUIjtzOjE6Im8iO3M6NDoi8J2XiCI7czoxOiJvIjtzOjQ6IvCdl7wiO3M6MToibyI7czo0OiLwnZiwIjtzOjE6Im8iO3M6NDoi8J2ZpCI7czoxOiJvIjtzOjQ6IvCdmpgiO3M6MToibyI7czozOiLhtI8iO3M6MToibyI7czozOiLhtJEiO3M6MToibyI7czozOiLqrL0iO3M6MToibyI7czoyOiLOvyI7czoxOiJvIjtzOjQ6IvCdm5AiO3M6MToibyI7czo0OiLwnZyKIjtzOjE6Im8iO3M6NDoi8J2dhCI7czoxOiJvIjtzOjQ6IvCdnb4iO3M6MToibyI7czo0OiLwnZ64IjtzOjE6Im8iO3M6Mjoiz4MiO3M6MToibyI7czo0OiLwnZuUIjtzOjE6Im8iO3M6NDoi8J2cjiI7czoxOiJvIjtzOjQ6IvCdnYgiO3M6MToibyI7czo0OiLwnZ6CIjtzOjE6Im8iO3M6NDoi8J2evCI7czoxOiJvIjtzOjM6IuKynyI7czoxOiJvIjtzOjI6ItC+IjtzOjE6Im8iO3M6Mzoi4YO/IjtzOjE6Im8iO3M6Mjoi1oUiO3M6MToibyI7czoyOiLXoSI7czoxOiJvIjtzOjI6ItmHIjtzOjE6Im8iO3M6NDoi8J64pCI7czoxOiJvIjtzOjQ6IvCeuaQiO3M6MToibyI7czo0OiLwnrqEIjtzOjE6Im8iO3M6Mzoi77urIjtzOjE6Im8iO3M6Mzoi77usIjtzOjE6Im8iO3M6Mzoi77uqIjtzOjE6Im8iO3M6Mzoi77upIjtzOjE6Im8iO3M6Mjoi2r4iO3M6MToibyI7czozOiLvrqwiO3M6MToibyI7czozOiLvrq0iO3M6MToibyI7czozOiLvrqsiO3M6MToibyI7czozOiLvrqoiO3M6MToibyI7czoyOiLbgSI7czoxOiJvIjtzOjM6Iu+uqCI7czoxOiJvIjtzOjM6Iu+uqSI7czoxOiJvIjtzOjM6Iu+upyI7czoxOiJvIjtzOjM6Iu+upiI7czoxOiJvIjtzOjI6ItuVIjtzOjE6Im8iO3M6Mzoi4LSgIjtzOjE6Im8iO3M6Mzoi4YCdIjtzOjE6Im8iO3M6NDoi8JCTqiI7czoxOiJvIjtzOjQ6IvCRo4giO3M6MToibyI7czo0OiLwkaOXIjtzOjE6Im8iO3M6NDoi8JCQrCI7czoxOiJvIjtpOjA7czoxOiJPIjtzOjI6It+AIjtzOjE6Ik8iO3M6Mzoi4KemIjtzOjE6Ik8iO3M6Mzoi4K2mIjtzOjE6Ik8iO3M6Mzoi44CHIjtzOjE6Ik8iO3M6NDoi8JGTkCI7czoxOiJPIjtzOjQ6IvCRo6AiO3M6MToiTyI7czo0OiLwnZ+OIjtzOjE6Ik8iO3M6NDoi8J2fmCI7czoxOiJPIjtzOjQ6IvCdn6IiO3M6MToiTyI7czo0OiLwnZ+sIjtzOjE6Ik8iO3M6NDoi8J2ftiI7czoxOiJPIjtzOjM6Iu+8ryI7czoxOiJPIjtzOjQ6IvCdkI4iO3M6MToiTyI7czo0OiLwnZGCIjtzOjE6Ik8iO3M6NDoi8J2RtiI7czoxOiJPIjtzOjQ6IvCdkqoiO3M6MToiTyI7czo0OiLwnZOeIjtzOjE6Ik8iO3M6NDoi8J2UkiI7czoxOiJPIjtzOjQ6IvCdlYYiO3M6MToiTyI7czo0OiLwnZW6IjtzOjE6Ik8iO3M6NDoi8J2WriI7czoxOiJPIjtzOjQ6IvCdl6IiO3M6MToiTyI7czo0OiLwnZiWIjtzOjE6Ik8iO3M6NDoi8J2ZiiI7czoxOiJPIjtzOjQ6IvCdmb4iO3M6MToiTyI7czoyOiLOnyI7czoxOiJPIjtzOjQ6IvCdmrYiO3M6MToiTyI7czo0OiLwnZuwIjtzOjE6Ik8iO3M6NDoi8J2cqiI7czoxOiJPIjtzOjQ6IvCdnaQiO3M6MToiTyI7czo0OiLwnZ6eIjtzOjE6Ik8iO3M6Mzoi4rKeIjtzOjE6Ik8iO3M6Mjoi0J4iO3M6MToiTyI7czoyOiLVlSI7czoxOiJPIjtzOjM6IuK1lCI7czoxOiJPIjtzOjM6IuGLkCI7czoxOiJPIjtzOjM6IuCsoCI7czoxOiJPIjtzOjQ6IvCQk4IiO3M6MToiTyI7czozOiLqk7MiO3M6MToiTyI7czo0OiLwkaK1IjtzOjE6Ik8iO3M6NDoi8JCKkiI7czoxOiJPIjtzOjQ6IvCQiqsiO3M6MToiTyI7czo0OiLwkJCEIjtzOjE6Ik8iO3M6NDoi8JCUliI7czoxOiJPIjtzOjM6IuKBsCI7czoxOiK6IjtzOjM6IuG1kiI7czoxOiK6IjtzOjI6IsWQIjtzOjE6ItYiO3M6Mzoi4o20IjtzOjE6InAiO3M6Mzoi772QIjtzOjE6InAiO3M6NDoi8J2QqSI7czoxOiJwIjtzOjQ6IvCdkZ0iO3M6MToicCI7czo0OiLwnZKRIjtzOjE6InAiO3M6NDoi8J2ThSI7czoxOiJwIjtzOjQ6IvCdk7kiO3M6MToicCI7czo0OiLwnZStIjtzOjE6InAiO3M6NDoi8J2VoSI7czoxOiJwIjtzOjQ6IvCdlpUiO3M6MToicCI7czo0OiLwnZeJIjtzOjE6InAiO3M6NDoi8J2XvSI7czoxOiJwIjtzOjQ6IvCdmLEiO3M6MToicCI7czo0OiLwnZmlIjtzOjE6InAiO3M6NDoi8J2amSI7czoxOiJwIjtzOjI6Is+BIjtzOjE6InAiO3M6Mjoiz7EiO3M6MToicCI7czo0OiLwnZuSIjtzOjE6InAiO3M6NDoi8J2boCI7czoxOiJwIjtzOjQ6IvCdnIwiO3M6MToicCI7czo0OiLwnZyaIjtzOjE6InAiO3M6NDoi8J2dhiI7czoxOiJwIjtzOjQ6IvCdnZQiO3M6MToicCI7czo0OiLwnZ6AIjtzOjE6InAiO3M6NDoi8J2ejiI7czoxOiJwIjtzOjQ6IvCdnroiO3M6MToicCI7czo0OiLwnZ+IIjtzOjE6InAiO3M6Mzoi4rKjIjtzOjE6InAiO3M6Mjoi0YAiO3M6MToicCI7czozOiLvvLAiO3M6MToiUCI7czozOiLihJkiO3M6MToiUCI7czo0OiLwnZCPIjtzOjE6IlAiO3M6NDoi8J2RgyI7czoxOiJQIjtzOjQ6IvCdkbciO3M6MToiUCI7czo0OiLwnZKrIjtzOjE6IlAiO3M6NDoi8J2TnyI7czoxOiJQIjtzOjQ6IvCdlJMiO3M6MToiUCI7czo0OiLwnZW7IjtzOjE6IlAiO3M6NDoi8J2WryI7czoxOiJQIjtzOjQ6IvCdl6MiO3M6MToiUCI7czo0OiLwnZiXIjtzOjE6IlAiO3M6NDoi8J2ZiyI7czoxOiJQIjtzOjQ6IvCdmb8iO3M6MToiUCI7czoyOiLOoSI7czoxOiJQIjtzOjQ6IvCdmrgiO3M6MToiUCI7czo0OiLwnZuyIjtzOjE6IlAiO3M6NDoi8J2crCI7czoxOiJQIjtzOjQ6IvCdnaYiO3M6MToiUCI7czo0OiLwnZ6gIjtzOjE6IlAiO3M6Mzoi4rKiIjtzOjE6IlAiO3M6Mjoi0KAiO3M6MToiUCI7czozOiLhj6IiO3M6MToiUCI7czozOiLhka0iO3M6MToiUCI7czozOiLqk5EiO3M6MToiUCI7czo0OiLwkIqVIjtzOjE6IlAiO3M6NDoi8J2QqiI7czoxOiJxIjtzOjQ6IvCdkZ4iO3M6MToicSI7czo0OiLwnZKSIjtzOjE6InEiO3M6NDoi8J2ThiI7czoxOiJxIjtzOjQ6IvCdk7oiO3M6MToicSI7czo0OiLwnZSuIjtzOjE6InEiO3M6NDoi8J2VoiI7czoxOiJxIjtzOjQ6IvCdlpYiO3M6MToicSI7czo0OiLwnZeKIjtzOjE6InEiO3M6NDoi8J2XviI7czoxOiJxIjtzOjQ6IvCdmLIiO3M6MToicSI7czo0OiLwnZmmIjtzOjE6InEiO3M6NDoi8J2amiI7czoxOiJxIjtzOjI6ItSbIjtzOjE6InEiO3M6Mjoi1aMiO3M6MToicSI7czoyOiLVpiI7czoxOiJxIjtzOjM6IuKEmiI7czoxOiJRIjtzOjQ6IvCdkJAiO3M6MToiUSI7czo0OiLwnZGEIjtzOjE6IlEiO3M6NDoi8J2RuCI7czoxOiJRIjtzOjQ6IvCdkqwiO3M6MToiUSI7czo0OiLwnZOgIjtzOjE6IlEiO3M6NDoi8J2UlCI7czoxOiJRIjtzOjQ6IvCdlbwiO3M6MToiUSI7czo0OiLwnZawIjtzOjE6IlEiO3M6NDoi8J2XpCI7czoxOiJRIjtzOjQ6IvCdmJgiO3M6MToiUSI7czo0OiLwnZmMIjtzOjE6IlEiO3M6NDoi8J2agCI7czoxOiJRIjtzOjM6IuK1lSI7czoxOiJRIjtzOjQ6IvCdkKsiO3M6MToiciI7czo0OiLwnZGfIjtzOjE6InIiO3M6NDoi8J2SkyI7czoxOiJyIjtzOjQ6IvCdk4ciO3M6MToiciI7czo0OiLwnZO7IjtzOjE6InIiO3M6NDoi8J2UryI7czoxOiJyIjtzOjQ6IvCdlaMiO3M6MToiciI7czo0OiLwnZaXIjtzOjE6InIiO3M6NDoi8J2XiyI7czoxOiJyIjtzOjQ6IvCdl78iO3M6MToiciI7czo0OiLwnZizIjtzOjE6InIiO3M6NDoi8J2ZpyI7czoxOiJyIjtzOjQ6IvCdmpsiO3M6MToiciI7czozOiLqrYciO3M6MToiciI7czozOiLqrYgiO3M6MToiciI7czozOiLhtKYiO3M6MToiciI7czozOiLisoUiO3M6MToiciI7czoyOiLQsyI7czoxOiJyIjtzOjM6IuqugSI7czoxOiJyIjtzOjI6IsqAIjtzOjE6InIiO3M6NDoi8J2IliI7czoxOiJSIjtzOjM6IuKEmyI7czoxOiJSIjtzOjM6IuKEnCI7czoxOiJSIjtzOjM6IuKEnSI7czoxOiJSIjtzOjQ6IvCdkJEiO3M6MToiUiI7czo0OiLwnZGFIjtzOjE6IlIiO3M6NDoi8J2RuSI7czoxOiJSIjtzOjQ6IvCdk6EiO3M6MToiUiI7czo0OiLwnZW9IjtzOjE6IlIiO3M6NDoi8J2WsSI7czoxOiJSIjtzOjQ6IvCdl6UiO3M6MToiUiI7czo0OiLwnZiZIjtzOjE6IlIiO3M6NDoi8J2ZjSI7czoxOiJSIjtzOjQ6IvCdmoEiO3M6MToiUiI7czoyOiLGpiI7czoxOiJSIjtzOjM6IuGOoSI7czoxOiJSIjtzOjM6IuGPkiI7czoxOiJSIjtzOjQ6IvCQkrQiO3M6MToiUiI7czozOiLhlociO3M6MToiUiI7czozOiLqk6MiO3M6MToiUiI7czo0OiLwlry1IjtzOjE6IlIiO3M6Mzoi772TIjtzOjE6InMiO3M6NDoi8J2QrCI7czoxOiJzIjtzOjQ6IvCdkaAiO3M6MToicyI7czo0OiLwnZKUIjtzOjE6InMiO3M6NDoi8J2TiCI7czoxOiJzIjtzOjQ6IvCdk7wiO3M6MToicyI7czo0OiLwnZSwIjtzOjE6InMiO3M6NDoi8J2VpCI7czoxOiJzIjtzOjQ6IvCdlpgiO3M6MToicyI7czo0OiLwnZeMIjtzOjE6InMiO3M6NDoi8J2YgCI7czoxOiJzIjtzOjQ6IvCdmLQiO3M6MToicyI7czo0OiLwnZmoIjtzOjE6InMiO3M6NDoi8J2anCI7czoxOiJzIjtzOjM6IuqcsSI7czoxOiJzIjtzOjI6Isa9IjtzOjE6InMiO3M6Mjoi0ZUiO3M6MToicyI7czozOiLqrqoiO3M6MToicyI7czo0OiLwkaOBIjtzOjE6InMiO3M6NDoi8JCRiCI7czoxOiJzIjtzOjM6Iu+8syI7czoxOiJTIjtzOjQ6IvCdkJIiO3M6MToiUyI7czo0OiLwnZGGIjtzOjE6IlMiO3M6NDoi8J2RuiI7czoxOiJTIjtzOjQ6IvCdkq4iO3M6MToiUyI7czo0OiLwnZOiIjtzOjE6IlMiO3M6NDoi8J2UliI7czoxOiJTIjtzOjQ6IvCdlYoiO3M6MToiUyI7czo0OiLwnZW+IjtzOjE6IlMiO3M6NDoi8J2WsiI7czoxOiJTIjtzOjQ6IvCdl6YiO3M6MToiUyI7czo0OiLwnZiaIjtzOjE6IlMiO3M6NDoi8J2ZjiI7czoxOiJTIjtzOjQ6IvCdmoIiO3M6MToiUyI7czoyOiLQhSI7czoxOiJTIjtzOjI6ItWPIjtzOjE6IlMiO3M6Mzoi4Y+VIjtzOjE6IlMiO3M6Mzoi4Y+aIjtzOjE6IlMiO3M6Mzoi6pOiIjtzOjE6IlMiO3M6NDoi8Ja8uiI7czoxOiJTIjtzOjQ6IvCQipYiO3M6MToiUyI7czo0OiLwkJCgIjtzOjE6IlMiO3M6Mzoi6p61IjtzOjE6It8iO3M6MjoizrIiO3M6MToi3yI7czoyOiLPkCI7czoxOiLfIjtzOjQ6IvCdm4MiO3M6MToi3yI7czo0OiLwnZu9IjtzOjE6It8iO3M6NDoi8J2ctyI7czoxOiLfIjtzOjQ6IvCdnbEiO3M6MToi3yI7czo0OiLwnZ6rIjtzOjE6It8iO3M6Mzoi4Y+wIjtzOjE6It8iO3M6NDoi8J2QrSI7czoxOiJ0IjtzOjQ6IvCdkaEiO3M6MToidCI7czo0OiLwnZKVIjtzOjE6InQiO3M6NDoi8J2TiSI7czoxOiJ0IjtzOjQ6IvCdk70iO3M6MToidCI7czo0OiLwnZSxIjtzOjE6InQiO3M6NDoi8J2VpSI7czoxOiJ0IjtzOjQ6IvCdlpkiO3M6MToidCI7czo0OiLwnZeNIjtzOjE6InQiO3M6NDoi8J2YgSI7czoxOiJ0IjtzOjQ6IvCdmLUiO3M6MToidCI7czo0OiLwnZmpIjtzOjE6InQiO3M6NDoi8J2anSI7czoxOiJ0IjtzOjM6IuG0myI7czoxOiJ0IjtzOjM6IuKKpCI7czoxOiJUIjtzOjM6IuKfmSI7czoxOiJUIjtzOjQ6IvCfnagiO3M6MToiVCI7czozOiLvvLQiO3M6MToiVCI7czo0OiLwnZCTIjtzOjE6IlQiO3M6NDoi8J2RhyI7czoxOiJUIjtzOjQ6IvCdkbsiO3M6MToiVCI7czo0OiLwnZKvIjtzOjE6IlQiO3M6NDoi8J2ToyI7czoxOiJUIjtzOjQ6IvCdlJciO3M6MToiVCI7czo0OiLwnZWLIjtzOjE6IlQiO3M6NDoi8J2VvyI7czoxOiJUIjtzOjQ6IvCdlrMiO3M6MToiVCI7czo0OiLwnZenIjtzOjE6IlQiO3M6NDoi8J2YmyI7czoxOiJUIjtzOjQ6IvCdmY8iO3M6MToiVCI7czo0OiLwnZqDIjtzOjE6IlQiO3M6MjoizqQiO3M6MToiVCI7czo0OiLwnZq7IjtzOjE6IlQiO3M6NDoi8J2btSI7czoxOiJUIjtzOjQ6IvCdnK8iO3M6MToiVCI7czo0OiLwnZ2pIjtzOjE6IlQiO3M6NDoi8J2eoyI7czoxOiJUIjtzOjM6IuKypiI7czoxOiJUIjtzOjI6ItCiIjtzOjE6IlQiO3M6Mzoi4Y6iIjtzOjE6IlQiO3M6Mzoi6pOUIjtzOjE6IlQiO3M6NDoi8Ja8iiI7czoxOiJUIjtzOjQ6IvCRorwiO3M6MToiVCI7czo0OiLwkIqXIjtzOjE6IlQiO3M6NDoi8JCKsSI7czoxOiJUIjtzOjQ6IvCQjJUiO3M6MToiVCI7czo0OiLwnZCuIjtzOjE6InUiO3M6NDoi8J2RoiI7czoxOiJ1IjtzOjQ6IvCdkpYiO3M6MToidSI7czo0OiLwnZOKIjtzOjE6InUiO3M6NDoi8J2TviI7czoxOiJ1IjtzOjQ6IvCdlLIiO3M6MToidSI7czo0OiLwnZWmIjtzOjE6InUiO3M6NDoi8J2WmiI7czoxOiJ1IjtzOjQ6IvCdl44iO3M6MToidSI7czo0OiLwnZiCIjtzOjE6InUiO3M6NDoi8J2YtiI7czoxOiJ1IjtzOjQ6IvCdmaoiO3M6MToidSI7czo0OiLwnZqeIjtzOjE6InUiO3M6Mzoi6p6fIjtzOjE6InUiO3M6Mzoi4bScIjtzOjE6InUiO3M6Mzoi6q2OIjtzOjE6InUiO3M6Mzoi6q2SIjtzOjE6InUiO3M6MjoiyosiO3M6MToidSI7czoyOiLPhSI7czoxOiJ1IjtzOjQ6IvCdm5YiO3M6MToidSI7czo0OiLwnZyQIjtzOjE6InUiO3M6NDoi8J2diiI7czoxOiJ1IjtzOjQ6IvCdnoQiO3M6MToidSI7czo0OiLwnZ6+IjtzOjE6InUiO3M6Mjoi1b0iO3M6MToidSI7czo0OiLwkJO2IjtzOjE6InUiO3M6NDoi8JGjmCI7czoxOiJ1IjtzOjM6IuKIqiI7czoxOiJVIjtzOjM6IuKLgyI7czoxOiJVIjtzOjQ6IvCdkJQiO3M6MToiVSI7czo0OiLwnZGIIjtzOjE6IlUiO3M6NDoi8J2RvCI7czoxOiJVIjtzOjQ6IvCdkrAiO3M6MToiVSI7czo0OiLwnZOkIjtzOjE6IlUiO3M6NDoi8J2UmCI7czoxOiJVIjtzOjQ6IvCdlYwiO3M6MToiVSI7czo0OiLwnZaAIjtzOjE6IlUiO3M6NDoi8J2WtCI7czoxOiJVIjtzOjQ6IvCdl6giO3M6MToiVSI7czo0OiLwnZicIjtzOjE6IlUiO3M6NDoi8J2ZkCI7czoxOiJVIjtzOjQ6IvCdmoQiO3M6MToiVSI7czoyOiLVjSI7czoxOiJVIjtzOjM6IuGIgCI7czoxOiJVIjtzOjQ6IvCQk44iO3M6MToiVSI7czozOiLhkYwiO3M6MToiVSI7czozOiLqk7QiO3M6MToiVSI7czo0OiLwlr2CIjtzOjE6IlUiO3M6NDoi8JGiuCI7czoxOiJVIjtzOjM6IuKIqCI7czoxOiJ2IjtzOjM6IuKLgSI7czoxOiJ2IjtzOjM6Iu+9liI7czoxOiJ2IjtzOjM6IuKFtCI7czoxOiJ2IjtzOjQ6IvCdkK8iO3M6MToidiI7czo0OiLwnZGjIjtzOjE6InYiO3M6NDoi8J2SlyI7czoxOiJ2IjtzOjQ6IvCdk4siO3M6MToidiI7czo0OiLwnZO/IjtzOjE6InYiO3M6NDoi8J2UsyI7czoxOiJ2IjtzOjQ6IvCdlaciO3M6MToidiI7czo0OiLwnZabIjtzOjE6InYiO3M6NDoi8J2XjyI7czoxOiJ2IjtzOjQ6IvCdmIMiO3M6MToidiI7czo0OiLwnZi3IjtzOjE6InYiO3M6NDoi8J2ZqyI7czoxOiJ2IjtzOjQ6IvCdmp8iO3M6MToidiI7czozOiLhtKAiO3M6MToidiI7czoyOiLOvSI7czoxOiJ2IjtzOjQ6IvCdm44iO3M6MToidiI7czo0OiLwnZyIIjtzOjE6InYiO3M6NDoi8J2dgiI7czoxOiJ2IjtzOjQ6IvCdnbwiO3M6MToidiI7czo0OiLwnZ62IjtzOjE6InYiO3M6Mjoi0bUiO3M6MToidiI7czoyOiLXmCI7czoxOiJ2IjtzOjQ6IvCRnIYiO3M6MToidiI7czozOiLqrqkiO3M6MToidiI7czo0OiLwkaOAIjtzOjE6InYiO3M6NDoi8J2IjSI7czoxOiJWIjtzOjI6ItmnIjtzOjE6IlYiO3M6Mjoi27ciO3M6MToiViI7czozOiLihaQiO3M6MToiViI7czo0OiLwnZCVIjtzOjE6IlYiO3M6NDoi8J2RiSI7czoxOiJWIjtzOjQ6IvCdkb0iO3M6MToiViI7czo0OiLwnZKxIjtzOjE6IlYiO3M6NDoi8J2TpSI7czoxOiJWIjtzOjQ6IvCdlJkiO3M6MToiViI7czo0OiLwnZWNIjtzOjE6IlYiO3M6NDoi8J2WgSI7czoxOiJWIjtzOjQ6IvCdlrUiO3M6MToiViI7czo0OiLwnZepIjtzOjE6IlYiO3M6NDoi8J2YnSI7czoxOiJWIjtzOjQ6IvCdmZEiO3M6MToiViI7czo0OiLwnZqFIjtzOjE6IlYiO3M6Mjoi0bQiO3M6MToiViI7czozOiLitLgiO3M6MToiViI7czozOiLhj5kiO3M6MToiViI7czozOiLhkK8iO3M6MToiViI7czozOiLqm58iO3M6MToiViI7czozOiLqk6YiO3M6MToiViI7czo0OiLwlryIIjtzOjE6IlYiO3M6NDoi8JGioCI7czoxOiJWIjtzOjQ6IvCQlJ0iO3M6MToiViI7czoyOiLJryI7czoxOiJ3IjtzOjQ6IvCdkLAiO3M6MToidyI7czo0OiLwnZGkIjtzOjE6InciO3M6NDoi8J2SmCI7czoxOiJ3IjtzOjQ6IvCdk4wiO3M6MToidyI7czo0OiLwnZSAIjtzOjE6InciO3M6NDoi8J2UtCI7czoxOiJ3IjtzOjQ6IvCdlagiO3M6MToidyI7czo0OiLwnZacIjtzOjE6InciO3M6NDoi8J2XkCI7czoxOiJ3IjtzOjQ6IvCdmIQiO3M6MToidyI7czo0OiLwnZi4IjtzOjE6InciO3M6NDoi8J2ZrCI7czoxOiJ3IjtzOjQ6IvCdmqAiO3M6MToidyI7czozOiLhtKEiO3M6MToidyI7czoyOiLRoSI7czoxOiJ3IjtzOjI6ItSdIjtzOjE6InciO3M6Mjoi1aEiO3M6MToidyI7czo0OiLwkZyKIjtzOjE6InciO3M6NDoi8JGcjiI7czoxOiJ3IjtzOjQ6IvCRnI8iO3M6MToidyI7czozOiLqroMiO3M6MToidyI7czo0OiLwkaOvIjtzOjE6IlciO3M6NDoi8JGjpiI7czoxOiJXIjtzOjQ6IvCdkJYiO3M6MToiVyI7czo0OiLwnZGKIjtzOjE6IlciO3M6NDoi8J2RviI7czoxOiJXIjtzOjQ6IvCdkrIiO3M6MToiVyI7czo0OiLwnZOmIjtzOjE6IlciO3M6NDoi8J2UmiI7czoxOiJXIjtzOjQ6IvCdlY4iO3M6MToiVyI7czo0OiLwnZaCIjtzOjE6IlciO3M6NDoi8J2WtiI7czoxOiJXIjtzOjQ6IvCdl6oiO3M6MToiVyI7czo0OiLwnZieIjtzOjE6IlciO3M6NDoi8J2ZkiI7czoxOiJXIjtzOjQ6IvCdmoYiO3M6MToiVyI7czoyOiLUnCI7czoxOiJXIjtzOjM6IuGOsyI7czoxOiJXIjtzOjM6IuGPlCI7czoxOiJXIjtzOjM6IuqTqiI7czoxOiJXIjtzOjM6IuGZriI7czoxOiJ4IjtzOjI6IsOXIjtzOjE6IngiO3M6Mzoi4qSrIjtzOjE6IngiO3M6Mzoi4qSsIjtzOjE6IngiO3M6Mzoi4qivIjtzOjE6IngiO3M6Mzoi772YIjtzOjE6IngiO3M6Mzoi4oW5IjtzOjE6IngiO3M6NDoi8J2QsSI7czoxOiJ4IjtzOjQ6IvCdkaUiO3M6MToieCI7czo0OiLwnZKZIjtzOjE6IngiO3M6NDoi8J2TjSI7czoxOiJ4IjtzOjQ6IvCdlIEiO3M6MToieCI7czo0OiLwnZS1IjtzOjE6IngiO3M6NDoi8J2VqSI7czoxOiJ4IjtzOjQ6IvCdlp0iO3M6MToieCI7czo0OiLwnZeRIjtzOjE6IngiO3M6NDoi8J2YhSI7czoxOiJ4IjtzOjQ6IvCdmLkiO3M6MToieCI7czo0OiLwnZmtIjtzOjE6IngiO3M6NDoi8J2aoSI7czoxOiJ4IjtzOjI6ItGFIjtzOjE6IngiO3M6Mzoi4ZWBIjtzOjE6IngiO3M6Mzoi4ZW9IjtzOjE6IngiO3M6Mzoi4ZmtIjtzOjE6IlgiO3M6Mzoi4pWzIjtzOjE6IlgiO3M6NDoi8JCMoiI7czoxOiJYIjtzOjQ6IvCRo6wiO3M6MToiWCI7czozOiLvvLgiO3M6MToiWCI7czozOiLihakiO3M6MToiWCI7czo0OiLwnZCXIjtzOjE6IlgiO3M6NDoi8J2RiyI7czoxOiJYIjtzOjQ6IvCdkb8iO3M6MToiWCI7czo0OiLwnZKzIjtzOjE6IlgiO3M6NDoi8J2TpyI7czoxOiJYIjtzOjQ6IvCdlJsiO3M6MToiWCI7czo0OiLwnZWPIjtzOjE6IlgiO3M6NDoi8J2WgyI7czoxOiJYIjtzOjQ6IvCdlrciO3M6MToiWCI7czo0OiLwnZerIjtzOjE6IlgiO3M6NDoi8J2YnyI7czoxOiJYIjtzOjQ6IvCdmZMiO3M6MToiWCI7czo0OiLwnZqHIjtzOjE6IlgiO3M6Mzoi6p6zIjtzOjE6IlgiO3M6MjoizqciO3M6MToiWCI7czo0OiLwnZq+IjtzOjE6IlgiO3M6NDoi8J2buCI7czoxOiJYIjtzOjQ6IvCdnLIiO3M6MToiWCI7czo0OiLwnZ2sIjtzOjE6IlgiO3M6NDoi8J2epiI7czoxOiJYIjtzOjM6IuKyrCI7czoxOiJYIjtzOjI6ItClIjtzOjE6IlgiO3M6Mzoi4rWdIjtzOjE6IlgiO3M6Mzoi4Zq3IjtzOjE6IlgiO3M6Mzoi6pOrIjtzOjE6IlgiO3M6NDoi8JCKkCI7czoxOiJYIjtzOjQ6IvCQirQiO3M6MToiWCI7czo0OiLwkIyXIjtzOjE6IlgiO3M6NDoi8JCUpyI7czoxOiJYIjtzOjI6IsmjIjtzOjE6InkiO3M6Mzoi4baMIjtzOjE6InkiO3M6Mzoi772ZIjtzOjE6InkiO3M6NDoi8J2QsiI7czoxOiJ5IjtzOjQ6IvCdkaYiO3M6MToieSI7czo0OiLwnZKaIjtzOjE6InkiO3M6NDoi8J2TjiI7czoxOiJ5IjtzOjQ6IvCdlIIiO3M6MToieSI7czo0OiLwnZS2IjtzOjE6InkiO3M6NDoi8J2VqiI7czoxOiJ5IjtzOjQ6IvCdlp4iO3M6MToieSI7czo0OiLwnZeSIjtzOjE6InkiO3M6NDoi8J2YhiI7czoxOiJ5IjtzOjQ6IvCdmLoiO3M6MToieSI7czo0OiLwnZmuIjtzOjE6InkiO3M6NDoi8J2aoiI7czoxOiJ5IjtzOjI6IsqPIjtzOjE6InkiO3M6Mzoi4bu/IjtzOjE6InkiO3M6Mzoi6q2aIjtzOjE6InkiO3M6MjoizrMiO3M6MToieSI7czozOiLihL0iO3M6MToieSI7czo0OiLwnZuEIjtzOjE6InkiO3M6NDoi8J2bviI7czoxOiJ5IjtzOjQ6IvCdnLgiO3M6MToieSI7czo0OiLwnZ2yIjtzOjE6InkiO3M6NDoi8J2erCI7czoxOiJ5IjtzOjI6ItGDIjtzOjE6InkiO3M6Mjoi0q8iO3M6MToieSI7czozOiLhg6ciO3M6MToieSI7czo0OiLwkaOcIjtzOjE6InkiO3M6Mzoi77y5IjtzOjE6IlkiO3M6NDoi8J2QmCI7czoxOiJZIjtzOjQ6IvCdkYwiO3M6MToiWSI7czo0OiLwnZKAIjtzOjE6IlkiO3M6NDoi8J2StCI7czoxOiJZIjtzOjQ6IvCdk6giO3M6MToiWSI7czo0OiLwnZScIjtzOjE6IlkiO3M6NDoi8J2VkCI7czoxOiJZIjtzOjQ6IvCdloQiO3M6MToiWSI7czo0OiLwnZa4IjtzOjE6IlkiO3M6NDoi8J2XrCI7czoxOiJZIjtzOjQ6IvCdmKAiO3M6MToiWSI7czo0OiLwnZmUIjtzOjE6IlkiO3M6NDoi8J2aiCI7czoxOiJZIjtzOjI6Is6lIjtzOjE6IlkiO3M6Mjoiz5IiO3M6MToiWSI7czo0OiLwnZq8IjtzOjE6IlkiO3M6NDoi8J2btiI7czoxOiJZIjtzOjQ6IvCdnLAiO3M6MToiWSI7czo0OiLwnZ2qIjtzOjE6IlkiO3M6NDoi8J2epCI7czoxOiJZIjtzOjM6IuKyqCI7czoxOiJZIjtzOjI6ItCjIjtzOjE6IlkiO3M6Mjoi0q4iO3M6MToiWSI7czozOiLhjqkiO3M6MToiWSI7czozOiLhjr0iO3M6MToiWSI7czozOiLqk6wiO3M6MToiWSI7czo0OiLwlr2DIjtzOjE6IlkiO3M6NDoi8JGipCI7czoxOiJZIjtzOjQ6IvCQirIiO3M6MToiWSI7czo0OiLwnZCzIjtzOjE6InoiO3M6NDoi8J2RpyI7czoxOiJ6IjtzOjQ6IvCdkpsiO3M6MToieiI7czo0OiLwnZOPIjtzOjE6InoiO3M6NDoi8J2UgyI7czoxOiJ6IjtzOjQ6IvCdlLciO3M6MToieiI7czo0OiLwnZWrIjtzOjE6InoiO3M6NDoi8J2WnyI7czoxOiJ6IjtzOjQ6IvCdl5MiO3M6MToieiI7czo0OiLwnZiHIjtzOjE6InoiO3M6NDoi8J2YuyI7czoxOiJ6IjtzOjQ6IvCdma8iO3M6MToieiI7czo0OiLwnZqjIjtzOjE6InoiO3M6Mzoi4bSiIjtzOjE6InoiO3M6Mzoi6q6TIjtzOjE6InoiO3M6NDoi8JGjhCI7czoxOiJ6IjtzOjQ6IvCQi7UiO3M6MToiWiI7czo0OiLwkaOlIjtzOjE6IloiO3M6Mzoi77y6IjtzOjE6IloiO3M6Mzoi4oSkIjtzOjE6IloiO3M6Mzoi4oSoIjtzOjE6IloiO3M6NDoi8J2QmSI7czoxOiJaIjtzOjQ6IvCdkY0iO3M6MToiWiI7czo0OiLwnZKBIjtzOjE6IloiO3M6NDoi8J2StSI7czoxOiJaIjtzOjQ6IvCdk6kiO3M6MToiWiI7czo0OiLwnZaFIjtzOjE6IloiO3M6NDoi8J2WuSI7czoxOiJaIjtzOjQ6IvCdl60iO3M6MToiWiI7czo0OiLwnZihIjtzOjE6IloiO3M6NDoi8J2ZlSI7czoxOiJaIjtzOjQ6IvCdmokiO3M6MToiWiI7czoyOiLOliI7czoxOiJaIjtzOjQ6IvCdmq0iO3M6MToiWiI7czo0OiLwnZunIjtzOjE6IloiO3M6NDoi8J2coSI7czoxOiJaIjtzOjQ6IvCdnZsiO3M6MToiWiI7czo0OiLwnZ6VIjtzOjE6IloiO3M6Mzoi4Y+DIjtzOjE6IloiO3M6Mzoi6pOcIjtzOjE6IloiO3M6NDoi8JGiqSI7czoxOiJaIjtzOjI6Isa/IjtzOjE6Iv4iO3M6Mjoiz7giO3M6MToi/iI7czoyOiLPtyI7czoxOiLeIjtzOjQ6IvCQk4QiO3M6MToi3iI7fQ==";

    private static function need_skip($string, $i)
    {
        $chars = " @\r\n\t.\"'";
        if (isset($string[$i]) && strpos($chars, $string[$i]) !== false) {
            $i++;
            return $i;
        }
        return false;
    }

    private static function match_shortopen_tag($string, $i, $needle, $j)
    {
        $pos_needle = false;
        $pos_string = false;
        if ((isset($needle[$j - 2]) && isset($string[$i - 2]))
            && (($needle[$j - 2] == '<') && ($string[$i - 2] == '<'))
            && (isset($needle[$j - 1]) && isset($string[$i - 1]))
            && ($needle[$j - 1] == '?' && $string[$i - 1] == '?')
        ) {
            $pos_needle = $j;
            $pos_string = $i;
        }
        if ($pos_needle && (isset($needle[$pos_needle]) && $needle[$pos_needle] === 'p')
            && (isset($needle[$pos_needle + 1]) && $needle[$pos_needle + 1] === 'h')
            && (isset($needle[$pos_needle + 2]) && $needle[$pos_needle + 2] === 'p')
        ) {
            $pos_needle = $pos_needle + 3;
        }

        if ($pos_string && (isset($string[$pos_string]) && $string[$pos_string] === 'p')
            && (isset($string[$pos_string + 1]) && $string[$pos_string + 1] === 'h')
            && (isset($string[$pos_string + 2]) && $string[$pos_string + 2] === 'p')
        ) {

            $pos_string = $pos_string + 3;
        }
        return [$pos_needle, $pos_string];
    }

    public static function unescape($string, $save_length = false) {
        if (strpos($string, '\\\'') === false && strpos($string, '\\"') === false && strpos($string, '\\/') === false) {
            return $string;
        }
        $strippedStr = stripcslashes($string);
        if (!$save_length) {
            return $strippedStr;
        } else {
            $strippedStr = self::extend_string_with_spaces($string, $strippedStr);
            return $strippedStr;
        }
    }

    public static function strip_whitespace($string, $save_length = false)
    {
        StringToStreamWrapper::prepare($string);
        $strippedStr = @php_strip_whitespace(StringToStreamWrapper::WRAPPER_NAME . '://');

        if (!$save_length) {
            return $strippedStr;
        } else {
            $strippedStr = self::extend_string_with_spaces($string, $strippedStr);
            return $strippedStr;
        }
    }

    public static function normalize($string, $save_length = false)
    {
        $search  = [ ' ;', ' =', ' ,', ' .', ' (', ' )', ' {', ' }', '; ', '= ', ', ', '. '
            , '( ', '( ', '{ ', '} ', ' !', ' >', ' <', ' _', '_ ', '< ',  '> ', ' $', ' %', '% '
            , '# ', ' #', '^ ', ' ^', ' &', '& ', ' ?', '? '];
        $replace = [  ';',  '=',  ',',  '.',  '(',  ')',  '{',  '}', ';',  '=',  ',',  '.'
            ,  '(',   ')', '{',  '}',   '!',  '>',  '<',  '_', '_',  '<',   '>',   '$',  '%', '%'
            ,  '#',   '#', '^',   '^',  '&', '&',   '?', '?'];

        $bad_chars = ['配', '内'];
        $string = str_replace($bad_chars, ' ', $string);
        $string = str_replace("\xEF\xBB\xBF", '   ', $string); //BOM

        $last_char = $string[-1] ?? '';

        if (!$save_length) {
            $string = str_replace('@', '', $string);
            $string = preg_replace('~\s+~msi', ' ', $string);
            $string = str_replace($search, $replace, $string);
            if (in_array($last_char, ["\r", "\n"]) && isset($string[-1]) && $string[-1] !== $last_char) {
                $string .= $last_char;
            }
        }

        $string = preg_replace_callback('~\bchr\(\s*([0-9a-fA-FxX\^]+)\s*\)~', function($m) use ($save_length) {
            if (strpos($m[1], '^') !== false) {
                $m[1] = Helpers::calc($m[1]);
            }
            if ($save_length) {
                return str_pad("'" . @chr(intval($m[1], 0)) . "'", strlen($m[0]), ' ');
            } else {
                return "'" . @chr(intval($m[1], 0)) . "'";
            }
        }, $string);

        $pattern = '~%([0-9a-fA-F]{2})~';
        if ($save_length && preg_match('~%25(%[0-9a-fA-F]{2}){2}(%25)?~ms', $string)) {
            $pattern = (isset($m[2]) && $m[2] !== '') ? '~%\s{0,2}([0-9a-fA-F\s]{2,6})~' : '~%\s{0,2}([0-9a-fA-F]{2})~';
        }

        for ($i = 0; $i < 2; $i++) {
            $string = preg_replace_callback($pattern, function($m) use ($save_length) {
                if ($save_length) {
                    return str_pad(chr(@hexdec($m[1])), strlen($m[0]), ' ');
                } else {
                    return @chr(hexdec($m[1]));
                }
            }, $string);
        }

        $iter = 0;
        $regexpHtmlAmp = '/\&[#\w ]{2,20} {0,2}; {0,2}/i';
        while ($iter < self::MAX_ITERATION && preg_match($regexpHtmlAmp, $string)) {
            $string = preg_replace_callback($regexpHtmlAmp, function ($m) use ($save_length) {
                if ($save_length) {
                    if (strpos($m[0], '  ') !== false) {
                        $m[0] = str_pad(str_replace(' ', '', $m[0]), strlen($m[0]));
                    }
                    $string = $m[0] == '&nbsp;' ? ' ' : $m[0];
                    return str_pad(@html_entity_decode($string, ENT_QUOTES | ENT_HTML5), strlen($m[0]), ' ', STR_PAD_LEFT);
                } else {
                    $string = $m[0] == '&nbsp;' ? ' ' : $m[0];
                    return @html_entity_decode($string, ENT_QUOTES | ENT_HTML5);
                }
            }, $string);
            $iter++;
        }
        
        $string = preg_replace_callback('/\\\\(?:x(?<hex>[a-fA-F0-9]{1,2})|(?<oct>[0-9]{2,3}))/i', function($m) use ($save_length) {
            $is_oct     = isset($m['oct']);
            $full_str   = $m[0];
            $value      = $is_oct ? $m['oct'] : $m['hex'];
            if ($save_length) {
                if ($is_oct) {
                    return str_pad(@chr(octdec($value)), strlen($full_str), ' ');
                }
                return str_pad(chr(@hexdec($value)), strlen($full_str), ' ');
            } else {
                if ($is_oct) {
                    return @chr(octdec($value));
                }
                return @chr(hexdec($value));
            }
        }, $string);
        
        $string = self::concatenate_strings($string, $save_length);

        $string = preg_replace_callback('~<title[^>]{0,99}>\s*\K(.{0,300}?)(?=<\/title>)~mis', function($m) use ($save_length) {
            if(preg_match('~(?:\w[^\x00-\x7F]{1,9}|[^\x00-\x7F]{1,9}\w)~', $m[1])) {
                return self::HomoglyphNormalize($m[1]);
            }
            return $m[1];
        }, $string);

        $string = preg_replace_callback('~<\?\s*p\s+h\s+p~msi', function ($m) {
            return str_pad('<?php', strlen($m[0]), ' ');
        }, $string);

        if (!$save_length) {
            $string = str_replace('<?php', '<?php ', $string);
            $string = preg_replace('~\s+~msi', ' ', $string);
            $string = trim($string);
        } else {
            $string = str_replace('<?php', '<?   ', $string);
        }

        return $string;
    }
    
    public static function get_end_of_extended_length($string_normalized, $string_orig, $start_pos)
    {
        if (strlen($string_normalized) == $start_pos + 1) {
            return $start_pos;
        }
        for ($i = $start_pos + 1, $iMax = strlen($string_normalized); $i < $iMax; $i++) {
            if ($string_orig[$i] === '\\' || $string_normalized[$i] !== ' ' || $string_orig[$i] === ' ') {
                break;
            }
        }
        return $i - 1;
    }

    public static function string_pos($string, $needle, $unescape = false)
    {
        $j      = 0;
        $skip   = false;
        $start  = false;
        $end    = 0;
        $last_tag = [false, false];

        $string_strip_whitespace = self::strip_whitespace($string, true);
        $needle = self::strip_whitespace($needle, false);

        $string = preg_replace_callback('~(<%3f|%253c%3f|%3c%3f)(php)?~msi', function ($m) {
            $ret = (isset($m[2]) && $m[2] !== '') ? '<?php' : '<?';
            return str_pad($ret, strlen($m[0]), ' ');
        }, $string_strip_whitespace);

        $string = preg_replace_callback('~(?:%3f>|%3f%253e|%3f%3e)~msi', function ($m) {
            return str_pad('?>', strlen($m[0]),  ' ', STR_PAD_LEFT);
        }, $string);

        $string = self::normalize($string, true);
        $needle = self::normalize($needle, false);
        $string = preg_replace_callback('~/\*[^\*]+\*/~', function ($m) {
            return str_repeat(' ', strlen($m[0]));
        }, $string); //php_strip_whitespace don't strip all comments, from xoredStrings type, hack for this
        $needle = preg_replace('~/\*[^\*]+\*/~', '', $needle); //php_strip_whitespace don't strip all comments, from xoredStrings type, hack for this

        $string = preg_replace_callback('~%\s*([\da-f])\s*([\da-f])~msi', function ($m) {
            return str_pad(chr(@hexdec($m[1] . $m[2])), strlen($m[0]), ' ');
        }, $string);

        if ($unescape) {
            $string = self::unescape($string, true);
            $string = self::normalize($string, true);
        }

        $needle = self::concatenate_strings($needle, true);

        for ($i = 0, $iMax = strlen($string); $i < $iMax; $i++) {
            if(trim($string[$i]) === '' && trim($needle[$j]) === '') {
                $string[$i] = $needle[$j] = ' ';
            }
            if ($string[$i] == $needle[$j]) {
                if ($j == 0) {
                    $start = $i;
                } elseif ($j == strlen($needle) - 1) {
                    $end = self::get_end_of_extended_length($string, $string_strip_whitespace, $i);
                    return [$start, $end];
                }
                $j++;
            } else {
                $match_php_tag = self::match_shortopen_tag($string, $i, $needle, $j);
                if ($match_php_tag[0] !== false && ($last_tag[0] !== $match_php_tag[0])) {
                    $j = $match_php_tag[0];
                }
                if ($match_php_tag[1] !== false && ($last_tag[1] !== $match_php_tag[1])) {
                    $i = $match_php_tag[1] - 1;
                }
                $last_tag = $match_php_tag;
                if ($match_php_tag[0] !== false || ($match_php_tag[1] !== false && (!empty($last_tag)))) {
                    continue;
                }
                $skip = self::need_skip($string, $i);
                if ($skip !== false && $start !== false) {
                    $i = $skip - 1;
                } else {
                    $j = 0;
                }
            }
        }
        return false;
    }

    private static function concatenate_strings($string, $save_length)
    {
        $string = preg_replace_callback('/[\'"]\s*?[\+\.]+\s*?[\'"]/smi', function($m) use ($save_length) {
            if ($save_length) {
                return str_repeat(' ', strlen($m[0]));
            } else {
                return '';
            }
        }, $string);
        return $string;
    }

    private static function HomoglyphNormalize($str)
    {
        if (!is_array(self::$confusables)) {
            self::$confusables = @unserialize(@base64_decode(self::$confusables));
        }
        return str_replace(array_keys(self::$confusables), array_values(self::$confusables), $str);
    }

    private static function extend_string_with_spaces($string, $strippedStr)
    {
        $strippedStr = str_replace('<?php  ', '<?php ', $strippedStr);

        $in_comment_ml = false;
        $in_comment_nl = false;
        $iMax = strlen($string);
        $jMax = strlen($strippedStr);

        if ($iMax === $jMax) {
            return $string;
        }

        $newStr = '';
        $j = 0;

        for ($i = 0; $i < $iMax; $i++) {
            if (isset($strippedStr[$j]) && trim($string[$i]) === trim($strippedStr[$j]) && !$in_comment_ml && !$in_comment_nl) {
                $newStr .= $string[$i];
                $j++;
            } else if ((trim($string[$i]) === '/' && trim($string[$i + 1]) === '*') && !$in_comment_ml && !$in_comment_nl) {
                $in_comment_ml = true;
                $newStr .= '  ';
                $i++;
            } else if ((trim($string[$i]) === '*' && trim($string[$i + 1]) === '/') && $in_comment_ml) {
                $in_comment_ml = false;
                $newStr .= ' ';
            } else if ((trim($string[$i]) === '/' && trim($string[$i + 1]) === '/') && !$in_comment_nl && !$in_comment_ml) {
                $in_comment_nl = true;
                $newStr .= ' ';
            } else if ((trim($string[$i]) === '#') && !$in_comment_nl && !$in_comment_ml) {
                $in_comment_nl = true;
                $newStr .= ' ';
            } else if (($string[$i] === "\n" || $string[$i] === "\r") && $in_comment_nl) {
                $in_comment_nl = false;
                $newStr .= ' ';
            } else if ($string[$i] === '?' && $string[$i + 1] === '>' && $in_comment_nl) {
                $in_comment_nl = false;
                $newStr .= $string[$i];
                $j++;
            } else if ((isset($strippedStr[$j]) && trim($string[$i]) !== trim($strippedStr[$j])) && ($in_comment_ml || $in_comment_nl)) {
                $newStr .= ' ';
            } else {
                $newStr .= ' ';
            }
        }
        return $newStr;
    }

    /**
     * @param array $confusables
     */
    public static function setConfusables(array $confusables)
    {
        self::$confusables = $confusables;
    }
}

class Encoding
{
    // Unicode BOM is U+FEFF, but after encoded, it will look like this.

    const UTF32_BIG_ENDIAN_BOM = "\x00\x00\xFE\xFF";
    const UTF32_LITTLE_ENDIAN_BOM = "\xFF\xFE\x00\x00";
    const UTF16_BIG_ENDIAN_BOM = "\xFE\xFF";
    const UTF16_LITTLE_ENDIAN_BOM = "\xFF\xFE";
    const UTF8_BOM = "\xEF\xBB\xBF";

    public static function detectUTFEncoding($text)
    {
        $first2 = substr($text, 0, 2);
        $first3 = substr($text, 0, 3);
        $first4 = substr($text, 0, 4);

        if ($first3 == self::UTF8_BOM) {
            return 'UTF-8';
        } elseif ($first4 == self::UTF32_BIG_ENDIAN_BOM) {
            return 'UTF-32BE';
        } elseif ($first4 == self::UTF32_LITTLE_ENDIAN_BOM) {
            return 'UTF-32LE';
        } elseif ($first2 == self::UTF16_BIG_ENDIAN_BOM) {
            return 'UTF-16BE';
        } elseif ($first2 == self::UTF16_LITTLE_ENDIAN_BOM) {
            return 'UTF-16LE';
        }
        return false;
    }

    public static function iconvSupported()
    {
        return (function_exists('iconv') && is_callable('iconv'));
    }

    public static function convertToCp1251($from, $str)
    {
        $ret = @iconv($from, 'CP1251//TRANSLIT', $str);
        if ($ret === false) {
            $ret = @iconv($from, 'CP1251//IGNORE', $str);
        }
        return $ret;
    }

    public static function convertToUTF8($from, $str)
    {
        return @iconv($from, 'UTF-8//IGNORE', $str);
    }
}
/**
 * Class SharedMem work with shared-memory
 */
class SharedMem
{

    private $instance = null;

    /**
     * SharedMem constructor.
     * @param int $key
     * @param string $mode
     * @param int $permissions
     * @param int $size
     */
    public function __construct(int $key , string $mode , int $permissions , int $size)
    {
        $this->instance = shmop_open($key, $mode, $permissions, $size);
    }

    /**
     * @param int $offset
     * @param int $size
     * @param bool $trim
     * @param bool $json
     * @return false|mixed|string
     */
    public function read(int $offset, int $size, bool $trim = true, bool $json = true)
    {
        $res = shmop_read($this->instance, $offset, $size);
        if ($trim) {
            $res = rtrim($res, "\0");
        }
        if ($json) {
            $res = json_decode($res, true);
        }
        return $res;
    }

    /**
     * @param string $data
     * @return int
     */
    public function write(array $data): int
    {
        shmop_write($this->instance, str_repeat("\0", shmop_size($this->instance)), 0);
        if (function_exists('json_encode')) {
            $res = shmop_write($this->instance, json_encode($data), 0);
        } else {
            $res = shmop_write($this->instance, serialize($data), 0);
        }
        return $res;
    }

    /**
     * @return int
     */
    public function getSize(): int
    {
        return shmop_size($this->instance);
    }

    /**
     * @return bool
     */
    public function delete(): bool
    {
        return shmop_delete($this->instance);
    }

    /**
     * @param bool $delete
     */
    public function close(bool $delete = false)
    {
        if ($delete) {
            shmop_delete($this->instance);
        }

        if (version_compare(phpversion('shmop'), '8.0.0', '<')) {
            shmop_close($this->instance);
        }

        $this->instance = null;
    }

    /**
     * @return bool
     */
    public function isValid()
    {
        if (version_compare(phpversion('shmop'), '8.0.0', '>=')) {
            return is_object($this->instance);
        }

        return is_resource($this->instance);
    }

    /**
     * @return false|resource|Shmop
     */
    public function getInstance()
    {
        return $this->instance;
    }
}

class ScanUnit
{
    public static function QCR_ScanContent($checkers, $l_Unwrapped, $l_Content, $signs, $debug = null, $precheck = null, $processResult = null, &$return = null)
    {
        $smart_skipped = false;
        $flag = false;
        foreach ($checkers as $checker => $full) {
            $l_pos = 0;
            $l_SignId = '';
            if (isset($precheck) && is_callable($precheck)) {
                if (!$precheck($checker, $l_Unwrapped) && ($full && !$precheck($checker, $l_Content))) {
                    $smart_skipped = true;
                    continue;
                }
            }
            $flag = ScanCheckers::{$checker}($l_Unwrapped, $l_pos, $l_SignId, $signs, $debug);
            if ($flag && isset($processResult) && is_callable($processResult)) {
                $processResult($checker, $l_Unwrapped, $l_pos, $l_SignId, $return);
            }

            if (!$flag && $full) {
                $flag = ScanCheckers::{$checker}($l_Content, $l_pos, $l_SignId, $signs, $debug);
                if ($flag && isset($processResult) && is_callable($processResult)) {
                    $processResult($checker, $l_Content, $l_pos, $l_SignId, $return);
                }
            }
            if ($flag) {
                return true;
            }
        }
        if (!$flag && $smart_skipped) {
            $return = [RapidScanStorageRecord::RX_SKIPPED_SMART, '', ''];
        }
        return false;
    }

    public static function Rescan($content, $signs, $debug = null, $deobfuscate = false, $processResult = null, &$return = null)
    {
        $checkers['CriticalPHP'] = true;
        $l_Unwrapped = Normalization::strip_whitespace($content);
        $l_UnicodeContent = Encoding::detectUTFEncoding($content);
        if ($l_UnicodeContent !== false) {
            if (Encoding::iconvSupported()) {
                $l_Unwrapped = Encoding::convertToCp1251($l_UnicodeContent, $l_Unwrapped);
            }
        }

        if ($deobfuscate) {
            $l_DeobfObj = new Deobfuscator($l_Unwrapped, $content);
            $l_DeobfType = $l_DeobfObj->getObfuscateType($l_Unwrapped);
        }

        if (isset($l_DeobfType) && $l_DeobfType != '') {
            $l_Unwrapped = $l_DeobfObj->deobfuscate();
        }

        $l_Unwrapped = Normalization::normalize($l_Unwrapped);
        return self::QCR_ScanContent($checkers, $l_Unwrapped, $content, $signs);
    }
}

class ScanCheckers
{
    const URL_GRAB = '~(?:<(script|iframe|object|embed|img|a)\s*.{0,300}?)?((?:https?:)?\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+\~#=]{2,256}\.[a-z]{2,4}\b(?:[-a-zA-Z0-9@:%_\+.\~#?&/=]*))(.{0,300}?</\1>)?~msi';

    public static function WarningPHP($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        foreach ($signs->_SusDB as $l_Item) {
            if (preg_match('~' . $l_Item . '~smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = LoadSignaturesForScan::getSigId($l_Found);
                    return true;
                }
            }
        }
        return false;
    }

    ////////////////////////////////////////////////////////////////////////////
    public static function Adware($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        $l_Res = false;

        foreach ($signs->_AdwareSig as $l_Item) {
            $offset = 0;
            while (preg_match('~' . $l_Item . '~smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos = $l_Found[0][1];
                    $l_SigId = 'adware';
                    return true;
                }

                $offset = $l_Found[0][1] + 1;
            }
        }

        return $l_Res;
    }

    ////////////////////////////////////////////////////////////////////////////
    public static function CheckException(&$l_Content, &$l_Found, $signs, $debug = null)
    {
        if (!(isset($signs->_ExceptFlex) && is_array($signs->_ExceptFlex))) {
            return false;
        }
        $l_FoundStrPlus = substr($l_Content, max($l_Found[0][1] - 10, 0), 70);

        foreach ($signs->_ExceptFlex as $l_ExceptItem) {
            if (@preg_match('~' . $l_ExceptItem . '~smi', $l_FoundStrPlus, $l_Detected)) {
                return true;
            }
        }

        return false;
    }

    ////////////////////////////////////////////////////////////////////////////
    public static function Phishing($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        $l_Res = false;

        foreach ($signs->_PhishingSig as $l_Item) {
            $offset = 0;
            while (preg_match('~' . $l_Item . '~smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = LoadSignaturesForScan::getSigId($l_Found);

                    if (is_object($debug) && $debug->getDebugMode() == true) {
                        echo "Phis: $l_Content matched [$l_Item] in $l_Pos\n";
                    }

                    return $l_Pos;
                }
                $offset = $l_Found[0][1] + 1;

            }
        }

        return $l_Res;
    }

    ////////////////////////////////////////////////////////////////////////////
    public static function CriticalJS($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        $l_Res = false;

        foreach ($signs->_JSVirSig as $l_Item) {
            $offset = 0;
            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_start = microtime(true);
            }
            $time = microtime(true);
            $res = preg_match('~' . $l_Item . '~smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset);
            if (class_exists('PerfomanceStats')) {
                PerfomanceStats::addPerfomanceItem(PerfomanceStats::PCRE_SCAN_STAT, microtime(true) - $time);
            }
            while ($res) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = LoadSignaturesForScan::getSigId($l_Found);

                    if (is_object($debug) && $debug->getDebugMode() == true) {
                        echo "JS: $l_Content matched [$l_Item] in $l_Pos\n";
                    }

                    $l_Res = true;
                    break;
                }

                $offset = $l_Found[0][1] + 1;
                $time = microtime(true);
                $res = preg_match('~' . $l_Item . '~smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset);
                if (class_exists('PerfomanceStats')) {
                    PerfomanceStats::addPerfomanceItem(PerfomanceStats::PCRE_SCAN_STAT, microtime(true) - $time);
                }
            }

            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_stop = microtime(true);
                $debug->addPerfomanceItem($l_Item, $stat_stop - $stat_start);
            }

        }

        return $l_Res;
    }

    public static function CriticalJS_PARA($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        foreach ($signs->X_JSVirSig as $l_Item) {
            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_start = microtime(true);
            }

            if (preg_match('~' . $l_Item . '~smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos   = $l_Found[0][1];
                    //$l_SigId = myCheckSum($l_Item);
                    $l_SigId = LoadSignaturesForScan::getSigId($l_Found);

                    if (is_object($debug) && $debug->getDebugMode() == true) {
                        echo "JS PARA: $l_Content matched [$l_Item] in $l_Pos\n";
                    }
                    return true;
                }
            }

            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_stop = microtime(true);
                $debug->addPerfomanceItem($l_Item, $stat_stop - $stat_start);
            }
        }
        return false;
    }

    ////////////////////////////////////////////////////////////////////////////
    public static function CriticalPHPGIF($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        if (strpos($l_Content, 'GIF89') === 0) {
            $l_Pos = 0;
            $l_SigId = 'GIF';
            if (is_object($debug) && $debug->getDebugMode() == true) {
                echo "CRIT 6: $l_Content matched [GIF] in $l_Pos\n";
            }

            return true;
        }
        return false;
    }

    public static function CriticalPHPUploader($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        // detect uploaders / droppers
        $l_Found = null;
        if ((strlen($l_Content) < 2048) && ((($l_Pos = strpos($l_Content, 'multipart/form-data')) > 0) || (($l_Pos = strpos($l_Content, '$_FILE[') > 0)) || (($l_Pos = strpos($l_Content, 'move_uploaded_file')) > 0) || (preg_match('|\bcopy\s*\(|smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)))) {
            if ($l_Found != null) {
                $l_Pos = $l_Found[0][1];
                $l_SigId = 'uploader';
            }
            if (is_object($debug) && $debug->getDebugMode() == true) {
                echo "CRIT 7: $l_Content matched [uploader] in $l_Pos\n";
            }

            return true;
        }
    }

    public static function CriticalPHP_3($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        foreach ($signs->X_FlexDBShe as $l_Item) {
            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_start = microtime(true);
            }

            if (preg_match('~' . $l_Item . '~smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = LoadSignaturesForScan::getSigId($l_Found);

                    if (is_object($debug) && $debug->getDebugMode() == true) {
                        echo "CRIT 3: $l_Content matched [$l_Item] in $l_Pos\n";
                    }

                    return true;
                }
            }

            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_stop = microtime(true);
                $debug->addPerfomanceItem($l_Item, $stat_stop - $stat_start);
            }
        }
        return false;
    }

    public static function CriticalPHP_2($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        foreach ($signs->XX_FlexDBShe as $l_Item) {
            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_start = microtime(true);
            }

            if (preg_match('~' . $l_Item . '~smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = LoadSignaturesForScan::getSigId($l_Found);

                    if (is_object($debug) && $debug->getDebugMode() == true) {
                        echo "CRIT 2: $l_Content matched [$l_Item] in $l_Pos\n";
                    }

                    return true;
                }
            }

            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_stop = microtime(true);
                $debug->addPerfomanceItem($l_Item, $stat_stop - $stat_start);
            }
        }
        return false;
    }

    public static function CriticalPHP_4($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        $l_Content_lo = strtolower($l_Content);

        foreach ($signs->_DBShe as $l_Item) {
            $l_Pos = strpos($l_Content_lo, $l_Item);
            if ($l_Pos !== false) {
                $l_SigId = AibolitHelpers::myCheckSum($l_Item);

                if (is_object($debug) && $debug->getDebugMode() == true) {
                    echo "CRIT 4: $l_Content matched [$l_Item] in $l_Pos\n";
                }

                return true;
            }
        }
        return false;
    }

    public static function CriticalPHP_5($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        $l_Content_lo = strtolower($l_Content);

        foreach ($signs->X_DBShe as $l_Item) {
            $l_Pos = strpos($l_Content_lo, $l_Item);
            if ($l_Pos !== false) {
                $l_SigId = AibolitHelpers::myCheckSum($l_Item);

                if (is_object($debug) && $debug->getDebugMode() == true) {
                    echo "CRIT 5: $l_Content matched [$l_Item] in $l_Pos\n";
                }

                return true;
            }
        }
        return false;
    }

    public static function CriticalPHP($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        foreach ($signs->_FlexDBShe as $l_Item) {
            $offset = 0;

            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_start = microtime(true);
            }
            $time = microtime(true);
            $res = preg_match('~' . $l_Item . '~smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset);
            if (class_exists('PerfomanceStats')) {
                PerfomanceStats::addPerfomanceItem(PerfomanceStats::PCRE_SCAN_STAT, microtime(true) - $time);
            }
            while ($res) {
                if (!self::CheckException($l_Content, $l_Found, $signs)) {
                    $l_Pos   = $l_Found[0][1];
                    //$l_SigId = myCheckSum($l_Item);
                    $l_SigId = LoadSignaturesForScan::getSigId($l_Found);

                    if (is_object($debug) && $debug->getDebugMode() == true) {
                        echo "CRIT 1: $l_Content matched [$l_Item] in $l_Pos\n";
                    }

                    return true;
                }

                $offset = $l_Found[0][1] + 1;
                $time = microtime(true);
                $res = preg_match('~' . $l_Item . '~smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset);
                if (class_exists('PerfomanceStats')) {
                    PerfomanceStats::addPerfomanceItem(PerfomanceStats::PCRE_SCAN_STAT, microtime(true) - $time);
                }
            }
            if (is_object($debug) && $debug->getDebugPerfomance() == true) {
                $stat_stop = microtime(true);
                $debug->addPerfomanceItem($l_Item, $stat_stop - $stat_start);
            }

        }

        return false;
    }

    public static function isOwnUrl($url, $own_domain)
    {
        if ($own_domain === null || $own_domain === '') {
            return false;
        }
        return (bool)preg_match('~^(http(s)?:)?//(www\.)?' . preg_quote($own_domain, '~') . '~msi', $url);
    }

    public static function isUrlInList($url, $list)
    {
        if (isset($list)) {
            foreach ($list as $item) {
                if (preg_match('~' . $item . '~msiS', $url, $id, PREG_OFFSET_CAPTURE)) {
                    return $id;
                }
            }
        }

        return false;
    }

    public static function UrlChecker($l_Content, &$l_Pos, &$l_SigId, $signs, $debug = null)
    {
        $l_Pos      = [];
        $l_SigId    = [];
        $offset     = 0;

        while (preg_match(self::URL_GRAB, $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
            if (!self::isOwnUrl($l_Found[2][0], $signs->getOwnUrl())
                && (isset($signs->whiteUrls) && !self::isUrlInList($l_Found[2][0], $signs->whiteUrls->getDb()))
            ) {
                if ($id = self::isUrlInList($l_Found[2][0], $signs->blackUrls->getDb())) {
                    if (isset($l_Found[1][0]) && $l_Found[1][0] !== '' && isset($l_Found[3][0]) && $l_Found[3][0] !== '') {
                        $l_Pos['black'][] = $l_Found[2][1];
                        $l_SigId['black'][] = $signs->blackUrls->getSig($id);
                    }
                } else {
                    $l_Pos['unk'][] = $l_Found[2][1];
                    $l_SigId['unk'][] = $l_Found[2][0];
                }
            }
            $offset = $l_Found[2][1] + strlen($l_Found[2][0]);
        }
        return !empty($l_Pos);
    }
}
class Helpers
{
    const REGEXP_BASE64_DECODE = '~base64_decode\s*\(\s*[\'"]([^\'"]*)[\'"]\s*\)~mis';
    const GOTO_MAX_HOPS        = 5000;

    /*************************************************************************************************************/
    /*                                Frequently used functions for deobfuscators                                */
    /*************************************************************************************************************/

    /**
     * This method normalizes string, converts characters to a readable form and some other things.
     * Also, the method can save the number of characters in the string by adding spaces if the number of characters has decreased.
     *
     * @param $string
     * @param false $save_length
     * @return string
     */
    public static function normalize($string, $save_length = false)
    {
        $search  = [ ' ;', ' =', ' ,', ' .', ' (', ' )', ' {', ' }', '; ', '= ', ', ', '. '
        , '( ', '( ', '{ ', '} ', ' !', ' >', ' <', ' _', '_ ', '< ',  '> ', ' $', ' %', '% '
        , '# ', ' #', '^ ', ' ^', ' &', '& ', ' ?', '? '];
        $replace = [  ';',  '=',  ',',  '.',  '(',  ')',  '{',  '}', ';',  '=',  ',',  '.'
        ,  '(',   ')', '{',  '}',   '!',  '>',  '<',  '_', '_',  '<',   '>',   '$',  '%', '%'
        ,  '#',   '#', '^',   '^',  '&', '&',   '?', '?'];

        if (!$save_length) {
            $string = str_replace('@', '', $string);
            $string = preg_replace('~\s+~smi', ' ', $string);
            $string = str_replace($search, $replace, $string);
        }

        $string = preg_replace_callback('~\bchr\(\s*([0-9a-fA-FxX\^]+)\s*\)~', static function($m) use ($save_length) {
            if (strpos($m[1], '^') !== false) {
                $m[1] = Helpers::calc($m[1]);
            }
            if ($save_length) {
                return str_pad("'" . @chr(intval($m[1], 0)) . "'", strlen($m[0]), ' ');
            } else {
                return "'" . @chr(intval($m[1], 0)) . "'";
            }
        }, $string);

        $string = preg_replace_callback('/\&\#([0-9]{1,3});/i', static function($m) use ($save_length) {
            if ($save_length) {
                return str_pad(@chr((int)$m[1]), strlen($m[0]), ' ');
            } else {
                return @chr((int)$m[1]);
            }
        }, $string);

        $string = preg_replace_callback('/\\\\(?:x(?<hex>[a-fA-F0-9]{1,2})|(?<oct>[0-9]{1,3}))/i', function($m) use ($save_length) {
            $is_oct     = isset($m['oct']);
            $full_str   = $m[0];
            $value      = $is_oct ? $m['oct'] : $m['hex'];
            if ($save_length) {
                if ($is_oct) {
                    return str_pad(@chr(octdec($value)), strlen($full_str), ' ');
                }
                return str_pad(chr(@hexdec($value)), strlen($full_str), ' ');
            } else {
                if ($is_oct) {
                    return @chr(octdec($value));
                }
                return @chr(hexdec($value));
            }
        }, $string);

        $string = preg_replace_callback('/[\'"]\s*?\.+\s*?[\'"]/smi', static function($m) use ($save_length) {
            if ($save_length) {
                return str_repeat(' ', strlen($m[0]));
            } else {
                return '';
            }
        }, $string);

        $string = preg_replace_callback('/[\'"]\s*?\++\s*?[\'"]/smi', static function($m) use ($save_length) {
            if ($save_length) {
                return str_repeat(' ', strlen($m[0]));
            } else {
                return '';
            }
        }, $string);

        if (!$save_length) {
            $string = str_replace('<?php', '<?php ', $string);
            $string = preg_replace('~\s+~', ' ', $string);
        }

        return $string;
    }

    /**
     * Code formatting. Not used in procu2 and ai-bolit
     *
     * @param $source
     * @return string
     */
    public static function format($source)
    {
        $t_count = 0;
        $in_object = false;
        $in_at = false;
        $in_php = false;
        $in_for = false;
        $in_comp = false;
        $in_quote = false;
        $in_var = false;

        if (!defined('T_ML_COMMENT')) {
            define('T_ML_COMMENT', T_COMMENT);
        }

        $result = '';
        @$tokens = token_get_all($source);
        foreach ($tokens as $token) {
            if (is_string($token)) {
                $token = trim($token);
                if ($token == '{') {
                    if ($in_for) {
                        $in_for = false;
                    }
                    if (!$in_quote && !$in_var) {
                        $t_count++;
                        $result = rtrim($result) . ' ' . $token . "\n" . str_repeat('    ', $t_count);
                    } else {
                        $result = rtrim($result) . $token;
                    }
                } elseif ($token == '$') {
                    $in_var = true;
                    $result .= $token;
                } elseif ($token == '}') {
                    if (!$in_quote && !$in_var) {
                        $new_line = true;
                        $t_count--;
                        if ($t_count < 0) {
                            $t_count = 0;
                        }
                        $result = rtrim($result) . "\n" . str_repeat('    ', $t_count) .
                            $token . "\n" . @str_repeat('    ', $t_count);
                    } else {
                        $result = rtrim($result) . $token;
                    }
                    if ($in_var) {
                        $in_var = false;
                    }
                } elseif ($token == ';') {
                    if ($in_comp) {
                        $in_comp = false;
                    }
                    if ($in_for) {
                        $result .= $token . ' ';
                    } else {
                        $result .= $token . "\n" . str_repeat('    ', $t_count);
                    }
                } elseif ($token == ':') {
                    if ($in_comp) {
                        $result .= ' ' . $token . ' ';
                    } else {
                        $result .= $token . "\n" . str_repeat('    ', $t_count);
                    }
                } elseif ($token == '(') {
                    $result .= ' ' . $token;
                } elseif ($token == ')') {
                    $result .= $token;
                } elseif ($token == '@') {
                    $in_at = true;
                    $result .= $token;
                } elseif ($token == '.') {
                    $result .= ' ' . $token . ' ';
                } elseif ($token == '=') {
                    $result .= ' ' . $token . ' ';
                } elseif ($token == '?') {
                    $in_comp = true;
                    $result .= ' ' . $token . ' ';
                } elseif ($token == '"') {
                    if ($in_quote) {
                        $in_quote = false;
                    } else {
                        $in_quote = true;
                    }
                    $result .= $token;
                } else {
                    $result .= $token;
                }
            } else {
                list($id, $text) = $token;
                switch ($id) {
                    case T_OPEN_TAG:
                    case T_OPEN_TAG_WITH_ECHO:
                        $in_php = true;
                        $result .= trim($text) . "\n";
                        break;
                    case T_CLOSE_TAG:
                        $in_php = false;
                        $result .= trim($text);
                        break;
                    case T_FOR:
                        $in_for = true;
                        $result .= trim($text);
                        break;
                    case T_OBJECT_OPERATOR:
                        $result .= trim($text);
                        $in_object = true;
                        break;

                    case T_ENCAPSED_AND_WHITESPACE:
                    case T_WHITESPACE:
                        $result .= trim($text);
                        break;
                    case T_RETURN:
                        $result = rtrim($result) . "\n" . str_repeat('    ', $t_count) . trim($text) . ' ';
                        break;
                    case T_ELSE:
                    case T_ELSEIF:
                        $result = rtrim($result) . ' ' . trim($text) . ' ';
                        break;
                    case T_CASE:
                    case T_DEFAULT:
                        $result = rtrim($result) . "\n" . str_repeat('    ', $t_count - 1) . trim($text) . ' ';
                        break;
                    case T_FUNCTION:
                    case T_CLASS:
                        $result .= "\n" . str_repeat('    ', $t_count) . trim($text) . ' ';
                        break;
                    case T_AND_EQUAL:
                    case T_AS:
                    case T_BOOLEAN_AND:
                    case T_BOOLEAN_OR:
                    case T_CONCAT_EQUAL:
                    case T_DIV_EQUAL:
                    case T_DOUBLE_ARROW:
                    case T_IS_EQUAL:
                    case T_IS_GREATER_OR_EQUAL:
                    case T_IS_IDENTICAL:
                    case T_IS_NOT_EQUAL:
                    case T_IS_NOT_IDENTICAL:
                    case T_LOGICAL_AND:
                    case T_LOGICAL_OR:
                    case T_LOGICAL_XOR:
                    case T_MINUS_EQUAL:
                    case T_MOD_EQUAL:
                    case T_MUL_EQUAL:
                    case T_OR_EQUAL:
                    case T_PLUS_EQUAL:
                    case T_SL:
                    case T_SL_EQUAL:
                    case T_SR:
                    case T_SR_EQUAL:
                    case T_START_HEREDOC:
                    case T_XOR_EQUAL:
                        $result = rtrim($result) . ' ' . trim($text) . ' ';
                        break;
                    case T_COMMENT:
                        $result = rtrim($result) . "\n" . str_repeat('    ', $t_count) . trim($text) . ' ';
                        break;
                    case T_ML_COMMENT:
                        $result = rtrim($result) . "\n";
                        $lines = explode("\n", $text);
                        foreach ($lines as $line) {
                            $result .= str_repeat('    ', $t_count) . trim($line);
                        }
                        $result .= "\n";
                        break;
                    case T_INLINE_HTML:
                        $result .= $text;
                        break;
                    default:
                        $result .= trim($text);
                        break;
                }
            }
        }
        return $result;
    }

    /**
     * Replace create_function(...) with function(){}
     *
     * @param $str
     * @return string
     */
    public static function replaceCreateFunction($str)
    {
        $hangs = 20;
        $str = stripcslashes($str);
        while (strpos($str, 'create_function') !== false && $hangs--) {
            $start_pos = strpos($str, 'create_function');
            $end_pos = 0;
            $brackets = 0;
            $started = false;
            $opened = 0;
            $closed = 0;
            for ($i = $start_pos, $iMax = strlen($str); $i < $iMax; $i++) {
                if ($str[$i] === '(') {
                    $started = true;
                    $brackets++;
                    $opened++;
                } else if ($str[$i] === ')') {
                    $closed++;
                    $brackets--;
                }
                if ($brackets == 0 && $started) {
                    $end_pos = $i + 1;
                    break;
                }
            }

            $cr_func = substr($str, $start_pos, $end_pos - $start_pos);
            $func = implode('function(', explode('create_function(\'', $cr_func, 2));
            $func = implode(') {', explode('\',\'', $func, 2));
            $func = substr($func, 0, -2) . '}';
            $str = str_replace($cr_func, $func, $str);
        }
        return $str;
    }

    /**
     * Calculate functions and simple mathematical expressions in code.
     * This function is applicable for simple expressions, if they are complex, then it may produce an incorrect result, in this case use MathCalc.
     *
     * @param $expr
     * @return string
     */
    public static function calc($expr)
    {
        if (is_array($expr)) {
            $expr = $expr[0];
        }
        $expr = str_replace([' ', "\r", "\n", "\t"], '', $expr);
        preg_match('~(chr|min|max|round)?\(([^\)]+)\)~msi', $expr, $expr_arr);
        if (@$expr_arr[1] == 'min' || @$expr_arr[1] == 'max') {
            return $expr_arr[1](explode(',', $expr_arr[2]));
        } elseif (@$expr_arr[1] == 'chr') {
            if ($expr_arr[2][0] === '(') {
                $expr_arr[2] = substr($expr_arr[2], 1);
            }
            $expr_arr[2] = self::calc($expr_arr[2]);
            return $expr_arr[1]((int)$expr_arr[2]);
        } elseif (@$expr_arr[1] == 'round') {
            $expr_arr[2] = self::calc($expr_arr[2]);
            return $expr_arr[1]($expr_arr[2]);
        } else {
            preg_match_all('~([\d\.a-fx]+)([\*\/\-\+\^\|\&])?~', $expr, $expr_arr);
            foreach ($expr_arr[1] as &$expr_arg) {
                if (strpos($expr_arg, "0x") !== false) {
                    $expr = str_replace($expr_arg, hexdec($expr_arg), $expr);
                    $expr_arg = hexdec($expr_arg);
                } else if ($expr_arg[0] === '0' && (strlen($expr_arg) > 1) && (strpos($expr_arg, '.') === false)) {
                    $expr = str_replace($expr_arg, octdec($expr_arg), $expr);
                    $expr_arg = octdec($expr_arg);
                }
            }
            if (in_array('*', $expr_arr[2]) !== false) {
                $pos = array_search('*', $expr_arr[2]);
                $res = $expr_arr[1][$pos] * $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '*' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '*' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('/', $expr_arr[2]) !== false) {
                $pos = array_search('/', $expr_arr[2]);
                $res = $expr_arr[1][$pos] / $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '/' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '/' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('-', $expr_arr[2]) !== false) {
                $pos = array_search('-', $expr_arr[2]);
                $res = $expr_arr[1][$pos] - $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '-' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '-' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('+', $expr_arr[2]) !== false) {
                $pos = array_search('+', $expr_arr[2]);
                $res = $expr_arr[1][$pos] + $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '+' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '+' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('^', $expr_arr[2]) !== false) {
                $pos = array_search('^', $expr_arr[2]);
                $res = (int)$expr_arr[1][$pos] ^ (int)$expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '^' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '^' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('|', $expr_arr[2]) !== false) {
                $pos = array_search('|', $expr_arr[2]);
                $res = $expr_arr[1][$pos] | $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '|' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '|' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } elseif (in_array('&', $expr_arr[2]) !== false) {
                $pos = array_search('&', $expr_arr[2]);
                $res = $expr_arr[1][$pos] & $expr_arr[1][$pos + 1];
                $pos_subst = strpos($expr, $expr_arr[1][$pos] . '&' . $expr_arr[1][$pos + 1]);
                $expr = substr_replace($expr, $res, $pos_subst, strlen($expr_arr[1][$pos] . '&' . $expr_arr[1][$pos + 1]));
                $expr = self::calc($expr);
            } else {
                return $expr;
            }

            return $expr;
        }
    }

    /**
     * Get code inside eval()
     *
     * @param $string
     * @return string
     */
    public static function getEvalCode($string)
    {
        preg_match("/eval\(([^\)]+)\)/msi", $string, $matches);
        return (empty($matches)) ? '' : end($matches);
    }

    /**
     * Method for unwrapping goto constructs.
     *
     * @param string $content
     * @return string
     */
    public static function unwrapGoto(&$content): string
    {
        if (!preg_match('~\$[^\[\(\)\]=\+\-]{1,20}~msi', $content)) {
            return $content;
        }
        $label_num = 0;
        $label_name = 'tmp_spec_label';

        $replaceVars = [];

        $content = preg_replace_callback('~\bgoto ([^\w;]+);~msi', function ($m) use (&$replaceVars, &$label_num, $label_name) {
            $label_num++;
            $newName = $label_name . $label_num;
            $replaceVars[] = [$m[1], $newName];
            return 'goto ' . $newName . '; ';
        }, $content);

        if (!empty($replaceVars)) {
            foreach ($replaceVars as $replaceVar) {
                $content = str_replace($replaceVar[0], $replaceVar[1], $content);
            }
        }

        $content = preg_replace_callback('~\b(if\s*(\([^)(]*+(?:(?2)[^)(]*)*+\))\s*)(goto\s*(?:\w+);)~msi', function($m) {
            return $m[1] . ' { ' . $m[3] . ' } ';
        }, $content);

        preg_match_all('~\bgoto\s?(\w+);~msi', $content, $gotoMatches, PREG_SET_ORDER);
        $gotoCount = count($gotoMatches);
        if (!$gotoCount || ($gotoCount <= 0 && $gotoCount > self::GOTO_MAX_HOPS)) {
            return $content;
        }

        $label_num = 0;
        $label_name = 'tmp_label';

        $res      = '';
        $hops     = self::GOTO_MAX_HOPS;
        if (preg_match('~(.*?)(?:goto\s\w+;|\w+:)~msi', $content, $m)) {
            $res .= trim($m[1]) . PHP_EOL;
        }

        if (preg_match('~\w{1,99}:\s*(<\?php)~msi', $content, $m, PREG_OFFSET_CAPTURE)) {
            $orig = substr($content, 0, $m[1][1]);
            $content = str_replace('<?php ' . $orig, '', $content);
        }

        $content = preg_replace_callback('~(?<!: )\}\s*goto\s*\w+;~mis', function($m) use (&$label_num, $label_name) {
            $label_num++;
            return $label_name . $label_num . ': ' . $m[0];
        }, $content);

        //try to match all if's conditions it can be if or loop
        preg_match_all('~\b(\w+):\s*if\s*(\([^)(]*+(?:(?2)[^)(]*)*+\))\s*\{\s*goto\s*(\w+); (' . $label_name . '\d+):\s*\}\s*goto\s*(\w+);~msi', $content, $conds, PREG_SET_ORDER);
        foreach ($conds as $cond) {
            preg_match('~\b\w+:\s*(\w+):\s*goto\s*' . $cond[1] . '~msi', $content, $while);
            if (preg_match('~\b\w+:\s*goto\s*' . $while[1] . ';\s*goto\s*\w+;~msi', $content) === 0) {
                $while = [];
            }
            preg_match('~\b' . $cond[5] . ':\s*(\w+):\s*goto\s*(\w+);~msi', $content, $do);
            preg_match('~\b(\w+):\s*' . $cond[3] . ':\s*goto\s*(\w+);~msi', $content, $m);
            preg_match('~\b(\w+):\s*goto\s*(\w+); goto\s*' . $m[1] . ';~msi', $content, $ifelse);
            preg_match('~\b(\w+):\s*\w+:\s*goto\s*' . $cond[1] . ';~msi', $content, $m);
            preg_match('~\b(\w+):[^:;]+[:;]\s*goto\s*(' . $m[1] . ');~msi', $content, $m);
            preg_match('~\b(\w+):\s*' . $ifelse[2] . ':\s*goto\s*(\w+);~msi', $content, $m);
            if (!empty($m) && ($m[2] === $cond[1])) { // if goto in last match point to this if statement - we have a loop, otherwise - if-else
                $ifelse = [];
            }

            if (empty($do) && empty($ifelse)) { //reverse conditions except do while & if else
                if ($cond[2][1] === '!') {
                    $cond[2] = substr_replace($cond[2], '', 1, 1);
                } else {
                    $cond[2] = '(!' . $cond[2] . ')';
                }
            }

            if (!empty($ifelse)) {
                $content = str_replace($cond[0],
                    $cond[1] . ': if ' . $cond[2] . ' { goto ' . $cond[3] . '; ' . $cond[4] . ': ' . '} else { goto ' . $cond[5] . ';',
                    $content);
                preg_match('~(\w+):\s*(' . $ifelse[2] . '):\s*goto\s*(\w+);~msi', $content, $m2);
                $content = str_replace($m2[0],
                    $m2[1] . ': goto ' . $cond[4] . '; ' . $m2[2] . ': } goto ' . $m2[3] . ';', $content);
            } elseif (!empty($do)) {
                preg_match('~(\w+):\s*(' . $cond[3] . '):\s*goto\s*~msi', $content, $match);
                $tmp = $cond[0];
                $content = str_replace($match[0], $match[1] . ': do { goto ' . $match[2] . '; ' . $match[2] . ': goto ',
                    $content);
                $cond[0] = $cond[1] . ': } while ' . $cond[2] . '; goto ' . $cond[5] . ';';
                $content = str_replace($tmp, $cond[0], $content);
            } else {
                if (!empty($while)) { //loop change if to while, reverse condition, exchange labels; in last goto $tmp_labelN
                    preg_match('~\w+:\s*goto\s*(' . $while[1] . ')~msi', $content, $match);
                    $content = str_replace($match[0], str_replace($match[1], $cond[4], $match[0]), $content);
                    $content = str_replace($cond[0],
                        $cond[1] . ': ' . 'while (' . $cond[2] . ') {' . 'goto ' . $cond[5] . '; ' . $cond[4] . ': } goto ' . $cond[3] . ';',
                        $content);
                } else { //just if - need to reverse condition and exchange labels; in last need goto to $tmp_labelN
                    $tmp = $cond[0];
                    $cond[0] = $cond[1] . ': ' . 'if ' . $cond[2] . ' { goto ' . $cond[5] . '; ' . $cond[4] . ': } goto ' . $cond[3] . ';';
                    $content = str_replace($tmp, $cond[0], $content);
                    preg_match('~(\w+):\s*(' . $cond[3] . '):\s*goto\s*(\w+)~msi', $content, $match);
                    $content = str_replace($match[0],
                        $match[1] . ': goto ' . $cond[4] . '; ' . $match[2] . ': goto ' . $match[3], $content);
                }
            }
        }

        $nextGotoPos = 0;
        while ($nextGotoPos !== false && $hops > 0 && preg_match('~goto\s(\w+);~msi',
                substr($content, $nextGotoPos),
                $gotoNameMatch,
                PREG_OFFSET_CAPTURE)) {

            $gotoNameStr    = $gotoNameMatch[1][0] . ':';
            $gotoNameStrLen = strlen($gotoNameStr);
            $gotoPos        = strpos($content, $gotoNameStr);
            $nextGotoPos    = strpos($content, 'goto ', $gotoPos);
            $cutUntilPos    = ($nextGotoPos - $gotoPos) - $gotoNameStrLen;

            $substr = '';

            if ($nextGotoPos) {
                $substr = substr($content, $gotoPos + $gotoNameStrLen, $cutUntilPos);
            } else {
                $substr = substr($content, $gotoPos + $gotoNameStrLen);
            }

            $piece = trim($substr);
            $piece === '' ?: $res .= $piece . ' ';
            $hops--;
        }
        $res = preg_replace('~\w{1,20}:~msi', '', $res);
        $res = stripcslashes($res);
        return $res;
    }

    /**
     * Get text inside quotes (' or ")
     *
     * @param $string
     * @return string
     */
    public static function getTextInsideQuotes($string)
    {
        if (preg_match_all('/("(.*)")/msi', $string, $matches)) {
            $array = end($matches);
            return @end($array);
        }

        if (preg_match_all('/\((\'(.*)\')/msi', $string, $matches)) {
            $array = end($matches);
            return @end($array);
        }

        return '';
    }

    /**
     * Get the value in quotes, the parity of the quotes is not checked.
     *
     * @param $string
     * @return array
     */
    public static function getNeedles($string)
    {
        preg_match_all("/'(.*?)'/msi", $string, $matches);

        return (empty($matches)) ? [] : $matches[1];
    }

    /**
     * Apply some formatting rules to the code
     *
     * @param $string
     * @return string
     */
    public static function formatPHP($string)
    {
        $string = str_replace('<?php', '', $string);
        $string = str_replace('?>', '', $string);
        $string = str_replace(PHP_EOL, "", $string);
        $string = str_replace(";", ";\n", $string);
        $string = str_replace("}", "}\n", $string);
        return $string;
    }

    /**
     * Parse array values om string and return array
     *
     * @param $string
     * @return array
     */
    public static function prepareArray($string)
    {
        $string = rtrim($string, ',');
        $array_string = Helpers::normalize($string);
        $list_str = explode(',', $array_string);
        $result = [];
        foreach ($list_str as $element) {
            $key = null;
            $value = $element;
            if (strpos($element, '=>') !== false) {
                list($key, $value) = explode('=>', $element);
            }
            $key = is_null($key) ? $key : trim($key, '\'"');
            $value = is_null($value) ? $value : trim($value, '\'"');

            if (is_null($key)) {
                $result[] = $value;
            }
            else {
                $result[$key] = $value;
            }
        }
        return $result;
    }

    /**
     * Detect text encoding
     *
     * @param $text
     * @return false|string
     */
    public static function detect_utf_encoding($text)
    {
        $first2 = substr($text, 0, 2);
        $first3 = substr($text, 0, 3);
        $first4 = substr($text, 0, 4);

        if ($first4 == chr(0x00) . chr(0x00) . chr(0xFE) . chr(0xFF)) {
            return 'UTF-32BE';
        } elseif ($first4 == chr(0xFF) . chr(0xFE) . chr(0x00) . chr(0x00)) {
            return 'UTF-32LE';
        } elseif ($first2 == chr(0xFE) . chr(0xFF)) {
            return 'UTF-16BE';
        } elseif ($first2 == chr(0xFF) . chr(0xFE)) {
            return 'UTF-16LE';
        }

        return false;
    }

    /**
     * Function safety check
     *
     * @param $func Function name
     * @return bool
     */
    public static function isSafeFunc($func)
    {
        $safeFuncs = [
            'base64_decode', 'gzinflate', 'gzdecode', 'gzuncompress', 'strrev', 'strlen',
            'str_rot13', 'urldecode', 'rawurldecode', 'stripslashes', 'chr',
            'htmlspecialchars_decode', 'convert_uudecode','pack', 'ord',
            'str_repeat', 'sprintf', 'str_replace', 'strtr', 'hex2bin',
            'helpers::unserialize',
        ];

        return in_array(strtolower($func), $safeFuncs);
    }

    /**
     * Convert the function to a safe one and return a boolean result was it possible to do it
     *
     * @param $func
     * @return bool
     */
    public static function convertToSafeFunc(&$func)
    {
        $replacedFuncs = [
            'unserialize' => 'Helpers::unserialize',
        ];

        $lowerFunc = strtolower($func);

        if (isset($replacedFuncs[$lowerFunc])) {
            $func = $replacedFuncs[$lowerFunc];
        }

        return self::isSafeFunc($func);
    }

    /**
     * Calculates a simple mathematical construct
     *
     * @param $task
     * @return string
     */
    public static function calculateMathStr($task)
    {
        $res = $task;

        while (preg_match('~\(?(\d+)\s?([+\-*\/])\s?(\d+)\)?~', $res, $subMatch)) {
            if (count($subMatch) === 4) {
                list($subSearch, $number_1, $operator, $number_2) = $subMatch;
                $res = str_replace($subSearch, self::calc("$number_1$operator$number_2"), $res);
            } else {
                return $res;
            }
        }

        return $res;
    }

    /**
     * From the content located in the input variable $content, get the values of the variables that can be calculated using the dictionary ($dictionary).
     * For example:
     * $dictionary: 'adnmpytr%uiqchsw_6jfoxkebzgl4v'
     * $content: $L1=$L1{8}.$L1{12}
     * return: ['$L1' => '%c']
     *
     * @param string $dictionary
     * @param string $content
     *
     * @return array
     */
    public static function getVarsFromDictionary($dictionary, $content) : array
    {
        $vars = [];
        preg_match_all('~(\$(?:[^\w]+|\w+)\s*=(\s?\.?\s?\$(?:[^\w]+|\w+)[{\[]\d+[\]}])+)~msi', $content, $concatMatches);
        for ($i = 0; $iMax = count($concatMatches[0]), $i <= $iMax; $i++) {
            preg_match_all('~(\$(?:[^\w]+|\w+)(=))?(\s?(\.?)\s?\$(?:[^\w]+|\w+)[{\[](\d+)[\]}])~msi',
                $concatMatches[0][$i], $varMatches);
            for ($j = 0; $jMax = count($varMatches[0]), $j < $jMax; $j++) {
                $varName = substr($varMatches[1][0], 0, -1);
                $value = $dictionary[(int)$varMatches[5][$j]] ?? '';

                if ($varMatches[2][$j] === '=') {
                    $vars[$varName] = $value;
                } else {
                    $vars[$varName] .= $value;
                }
            }
        }
        return $vars;
    }

    /**
     * From the content located in the input variable $content, calculate the variable values of which are concatenated from the variables of the dictionaries located in $vars.
     * Dictionary variables must already be in $vars when the function is run.
     *
     * @param array  $vars
     * @param string $content
     *
     * @return array
     */
    public static function getVarsFromDictionaryDynamically(array &$vars = [], string $content = ''): array
    {
        preg_match_all('~(\$\w+)(\.)?\s?=\s?(?:\$\w+[{\[]?\d+[}\]]?\.?)+;~msi', $content, $varsMatches, PREG_SET_ORDER);
        foreach ($varsMatches as $varsMatch) {
            preg_match_all('~(\$\w+)[{\[]?(\d+)?[}\]]?~msi', $varsMatch[0], $subVarsMatches, PREG_SET_ORDER);
            $concat = '';
            foreach ($subVarsMatches as $subVarsMatch) {
                if (isset($subVarsMatch[2])) {
                    $concat .= $vars[$subVarsMatch[1]][(int)$subVarsMatch[2]] ?? '';
                } else if ($varsMatch[1] !== $subVarsMatch[1]) {
                    $concat .= $vars[$subVarsMatch[1]];
                }
            }
            if (isset($vars[$varsMatch[1]])) {
                $vars[$varsMatch[1]] .= $concat;
            } else {
                $vars[$varsMatch[1]] = $concat;
            }
        }
        return $vars;
    }

    /**
     * Concatenate content of variables.
     * Examples: CheckDeobfuscationHelpersTest::testConcatVariableValues
     *
     * @param string $str
     * @return string
     */
    public static function concatVariableValues($str) : string
    {
        preg_match_all('/\$\w+\s?(\.?)=\s?"([\w=\+\/]+)"/', $str, $concatVars);
        $strVar = '';
        foreach ($concatVars[2] as $index => $concatVar) {
            if ($concatVars[1][$index] === '.') {
                $strVar .= $concatVar;
            } else {
                $strVar = $concatVar;
            }
        }
        return $strVar;
    }

    /**
     * Concatenate simple strings inside which there may be chunks of PHP code
     * Examples: CheckDeobfuscationHelpersTest::testConcatStr
     *
     * @param string $str
     * @return string
     */
    public static function concatStr($str) : string
    {
        preg_match_all('~(\.?)\s?[\'"]([\w=\+/%&();]+)[\'"]\s?~msi', $str, $concatStrings);
        $strVar = '';
        foreach ($concatStrings[2] as $index => $concatString) {
            if ($concatStrings[1][$index] === '.') {
                $strVar .= $concatString;
            } else {
                $strVar = $concatString;
            }
        }
        return $strVar;
    }

    /**
     * Concats simple strings without variable in content globally
     * Examples: CheckDeobfuscationHelpersTest::concatStringsInContent()
     *
     * @param string $str
     * @return string
     */
    public static function concatStringsInContent($str) : string
    {
        $strVar = preg_replace_callback('~(?:[\'"][\w=();]*[\'"]\.?){2,}~msi', static function ($m) {
            return '\'' . self::concatStr($m[0]) . '\'';
        }, $str);
        return $strVar;
    }

    /**
     * Replace the elements of the dictionary array with its values.
     * Examples: CheckDeobfuscationHelpersTest::testReplaceVarsFromDictionary()
     *
     * @param string $dictionaryVar
     * @param array $dictionaryValue
     * @param string $str
     * @param bool $quote
     *
     * @return string
     */
    public static function replaceVarsFromDictionary($dictionaryVar, $dictionaryValue, $str, $quote = true) : string
    {
        $result = $str;
        $result = preg_replace_callback('~(?:(\$(?:GLOBALS\[[\'"])?\w+(?:[\'"]\])?)[\[{][\'"]?(\d+)[\'"]?[\]}]\s?(\.)?\s?)~msi',
            function ($match) use ($dictionaryValue, $dictionaryVar, $quote) {
                if ($match[1] !== $dictionaryVar && !isset($dictionaryValue[(int)$match[2]])) {
                    return $match[0];
                }
                $lastChar = $match[3] ?? '';
                $value = $dictionaryValue[(int)$match[2]];
                $value = str_replace(['\'', '.'], ['@@quote@@', '@@dot@@'], $value);
                $value = $quote ? '\'' . $value . '\'' : $value;
                return $value . $lastChar;
            },
            $result
        );
        $result = str_replace('\'.\'', '', $result);
        $result = str_replace(['@@quote@@', '@@dot@@'], ['\\\'', '.'], $result);
        return $result;
    }

    /**
     * @param string $arrayName
     * @param array  $array
     * @param string $str
     *
     * @return string
     */
    public static function replaceVarsByArrayName(string $arrayName, array $array, string $str): string
    {
        $result = preg_replace_callback('~\s?(\$\w+)\s?\[\s?(\d+)\s?\]\s?~msi',
            function ($match) use ($array, $arrayName) {
                if ($match[1] !== $arrayName) {
                    return $match[0];
                }
                return $array[$match[2]] ?? $match[0];
            },
            $str
        );

        return $result;
    }

    /**
     * Collects simple or concated vars from str
     * @param string $str
     * @param string $trimQuote
     * @param array $vars
     * @param bool $remove
     *
     * @return array
     */
    public static function collectVars(&$str, string $trimQuote = '"', &$vars = [], $remove = false) : array
    {
        if (!is_string($str)) {
            return $vars;
        }
        preg_match_all('~(\$\w+)\s?(\.)?=\s?([\'"].*?[\'"]);~msi', $str, $matches);

        foreach ($matches[1] as $index => $match) {
            $varName = $match;
            $varValue = str_replace("$trimQuote.$trimQuote", '', $matches[3][$index]);
            $varValue = stripcslashes(trim($varValue, $trimQuote));
            if ($matches[2][$index] !== '.') {
                $vars[$varName] = $varValue;
            } else {
                $vars[$varName] .= $varValue;
            }
        }
        if ($remove) {
            $str = str_replace($matches[0], '', $str);
        }

        return $vars;
    }

    /**
     * Collects concated variable vars or str from str
     * @param string $str
     * @param string $trimQuote
     * @param array $vars
     * @param bool $remove
     *
     */
    public static function collectConcatedVars(&$str, string $trimQuote = '"', &$vars = [], $remove = false): array
    {
        if (!is_string($str)) {
            return $vars;
        }
        preg_match_all('~(\$\w+)\s?(\.)?=((?:\s?\.?\s?(?:[\'"][^"\']+[\'"]|\$\w{1,50}))+);~msi', $str, $matches, PREG_SET_ORDER);

        foreach ($matches as $match) {
            $varName = $match[1];
            $varValue = '';

            preg_match_all('~[\'"]([^"\']+)[\'"]|(\$\w{1,50})~msi', $match[3], $varsMatch, PREG_SET_ORDER);
            foreach ($varsMatch as $varMatch) {

                if ($varMatch[1] !== '') {
                    $varValue .= $varMatch[1];
                } else {
                    $varValue .= $vars[$varMatch[2]] ?? '';
                }

                $varValue = str_replace("$trimQuote.$trimQuote", '', $varValue);
                $varValue = stripcslashes(trim($varValue, $trimQuote));
            }

            if ($match[2] !== '.') {
                $vars[$varName] = $varValue;
            } else {
                $vars[$varName] .= $varValue;
            }

            if ($remove) {
                $str = str_replace($match[0], '', $str);
            }
        }

        return $vars;
    }

    /**
     * Collects simple or concated str
     * @param string $str
     * @param string $trimQuote
     *
     * @return string
     */
    public static function collectStr($str, string $trimQuote = '"') : string
    {
        preg_match('~["\'\w%=\.\+\/]+~msi', $str, $match);

        $str = str_replace("$trimQuote.$trimQuote", '', $match[0]);
        $str = trim($str, $trimQuote);

        return $str;
    }

    /**
     * Collects function wrapped vars with one arg from str
     * ex. var1 = base64_decode(str1); var2 = gzinflate(str2); and etc.
     *
     * @param string $str
     *
     * @return array
     */
    public static function collectFuncVars(string &$str, &$vars = [], $quotes = true, $delete = false): array
    {
        preg_match_all('~(\$\w+)\s*=\s*(\w+)\([\'"]([\w+/=]+)[\'"](?:,\s*[\'"]([\w+/=]*)[\'"],\s*[\'"]([\w+/=]+)[\'"])?\);~msi', $str, $matches, PREG_SET_ORDER);

        foreach ($matches as $match) {
            $func = $match[2];
            $param1 = $match[3];
            $param2 = $match[4];
            $param3 = $match[5];

            if (self::convertToSafeFunc($func)) {
                if ($func === 'str_replace') {
                    $ret = @$func($param1, $param2, $param3);
                } else {
                    $ret = @$func($param1);
                }
            }
            $vars[$match[1]] = self::convertToSafeFunc($ret) ? $ret : ($quotes ? "'$ret'" : $ret);

            if ($delete) {
                $str = str_replace($match[0], '', $str);
            }
        }

        return $vars;
    }

    /**
     * @param array  $vars
     * @param string $str
     *
     * @return string
     */
    public static function replaceVarsFromArray(array $vars, string $str, bool $isFunc = false, $toStr = false) : string
    {
        $result = $str;

        uksort($vars, static function($a, $b) {
            return strlen($b) <=> strlen($a);
        });
        foreach ($vars as $name => $value) {
            $sub_name = substr($name, 1);
            $result = preg_replace_callback('~{?(@)?\${?[\'"]?GLOBALS[\'"]?}?\[[\'"](\w+)[\'"]\]}?~msi',
                function ($m) use ($value, $sub_name) {
                    if ($m[2] !== $sub_name) {
                        return $m[0];
                    }
                    return $m[1] . $value;
                }, $result);

            if (!is_string($value)) {
                continue;
            }
            $result = str_replace(['{' . $name . '}', $name . '('], [$value, trim($value, '\'"') . '('],
                $result);

            if (!$isFunc && !$toStr) {
                $result = str_replace($name, $value, $result);
            } else if ($toStr) {
                $result = str_replace($name, "'$value'", $result);
            }

        }

        return $result;
    }

    /**
     * @param $str
     * @return array
     */
    public static function collectVarsChars($str)
    {
        $vars = [];
        preg_match_all('~(\$\w+)=\'(\w)\';~msi', $str, $matches, PREG_SET_ORDER);
        foreach ($matches as $m) {
            $vars[$m[1]] = $m[2];
        }
        return $vars;
    }

    /**
     * Removes duplicated string variables after replacing
     *
     * @param string $str
     *
     * @return string
     */
    public static function removeDuplicatedStrVars($str) : string
    {
        return preg_replace('~[\'"]?([^\'"]+)[\'"]?\s?=\s?[\'"]?\1[\'"]?;~msi','', $str);
    }

    /**
     * @param $chars
     * @param $str
     * @return array
     */
    public static function assembleStrings($chars, $str)
    {
        $vars = [];
        array_walk($chars, static function(&$x) {
            $x = "'$x'";
        });
        $parts = explode(';', $str);
        foreach ($parts as &$part) {
            $vals = explode('=', $part);
            $part = str_replace($vals[1], strtr($vals[1], $chars), $part);
        }
        $str = implode(';', $parts);
        $vars = self::collectVars($str, '\'');
        return $vars;
    }

    /**
     * Expand base64decode() function
     *
     * @param string $str
     * @param string $quote
     * @return string
     */
    public static function replaceBase64Decode($str, $quote = '\'')
    {
        return preg_replace_callback(self::REGEXP_BASE64_DECODE, static function ($m) use ($quote) {
            return $quote . base64_decode($m[1]) . $quote;
        }, $str);
    }

    /**
     * Calc min(), max() and round().
     * This function can be used with simple constructions, if they are complex, then it is better to use a separate MathCalc class.
     *
     * @param string $string
     * @param int $max_iterations
     * @return string
     */
    public static function replaceMinMaxRound($string, $max_iterations = 15)
    {
        $i = 0;
        $regexp_for_multi_min_max_round = '~(?:min|max|round)\(\s*\d+[\.\,\|\s\|+\|\-\|\*\|\/]([\d\s\.\,\+\-\*\/]+)?\)~msi';
        while (preg_match($regexp_for_multi_min_max_round, $string) && $i < $max_iterations) {
            $string = preg_replace_callback($regexp_for_multi_min_max_round, ['Helpers','calc'], $string);
            $i++;
        }

        $regexp_for_single_min_max_round = '~(?:min|max|round)\(\s*\d+\s*\)~msi';
        while (preg_match($regexp_for_single_min_max_round, $string) && $i < $max_iterations) {
            $string = preg_replace_callback($regexp_for_single_min_max_round, ['Helpers','calc'], $string);
            $i++;
        }

        $regexp_for_brackets = '~\(\s*\d+[\.\|\s\|+\|\-\|\*\|\/]([\d\s\.\+\-\*\/]+)?\)~msi';
        while (preg_match($regexp_for_brackets, $string) && $i < $max_iterations) {
            $string = preg_replace_callback($regexp_for_brackets, ['Helpers','calc'], $string);
            $i++;
        }

        return $string;
    }

    /**
     * Calc XOR with key
     *
     * @param string $encrypted
     * @param string $key
     * @return string
     */
    public static function xorWithKey($encrypted, $key)
    {
        $res = '';
        for ($i = 0, $iMax = strlen($encrypted); $i < $iMax; ) {
            for ($j = 0; $j < strlen($key) && $i < strlen($encrypted); $j++, $i++) {
                $res .= $encrypted[$i] ^ $key[$j];
            }
        }
        return $res;
    }

    /**
     * Similar to the native PHP function unserialize(), but it is safe as it only supports simple data types.
     *
     * @param string $string
     * @return array|bool|float|int|string|null
     */
    public static function unserialize(&$string)
    {
        $type = substr($string, 0, 2);
        $string = substr($string, 2);
        switch ($type) {
            case 'N;':
                return null;
            case 'b:':
                list($ret, $string) = explode(';', $string, 2);
                return (bool)(int)$ret;
            case 'i:':
                list($ret, $string) = explode(';', $string, 2);
                return (int)$ret;
            case 'd:':
                list($ret, $string) = explode(';', $string, 2);
                return (float)$ret;
            case 's:':
                list($length, $string) = explode(':', $string, 2);
                $length = (int) $length;
                if (($length > strlen($string) - 3) || ($string[0] !== '"') || (substr($string, $length + 1, 2) !== '";')) {
                    return '';
                }
                $ret = substr($string, 1, $length);
                $string = substr($string, $length + 3);
                return $ret;
            case 'a:':
                $ret = [];
                list($length, $string) = explode(':', $string, 2);
                if ($string[0] !== '{') {
                    return '';
                }
                $length = (int) $length;
                $string = substr($string, 1);
                for ($i= 0; $i < $length; $i++) {
                    $ret[self::unserialize($string)] = self::unserialize($string);
                }
                if ($string === '') {
                    return $ret;
                }
                $end = substr($string, 0, 2);
                if ($end !== '' && $end !== '};' && $end !== '}' && $end !== '}}') {
                    return '';
                }
                $string = substr($string, 2);
                return $ret;
            case 'O:':
                list($length, $string) = explode(':', $string, 2);
                $length = (int) $length;
                $string = substr($string, $length + 3);
                list($length, $string) = explode(':', $string, 2);
                $string = preg_replace('~{([^{}]*+(?:(?R)[^{}]*)*+)}~msi', '', $string);
                return '';
            default:
                return '';
        }
    }

    /**
     * Post processing after deobfuscation
     *
     * @param string $deobfuscated
     * @return string
     */
    public static function postProcess($deobfuscated) : string
    {
        $deobfuscated = preg_replace_callback('~"[\w\\\\\s=;_<>&/\.-]+"~msi', static function ($matches) {
            return preg_match('~\\\\x[2-7][0-9a-f]|\\\\1[0-2][0-9]|\\\\[3-9][0-9]|\\\\0[0-4][0-9]|\\\\1[0-7][0-9]~msi', $matches[0]) ? stripcslashes($matches[0]) : $matches[0];
        }, $deobfuscated);

        $deobfuscated = preg_replace_callback('~echo\s*"((.*?[^\\\\])??((\\\\\\\\)+)?+)"~msi', static function ($matches) {
            return preg_match('~\\\\x[2-7][0-9a-f]|\\\\1[0-2][0-9]|\\\\[3-9][0-9]|\\\\0[0-4][0-9]|\\\\1[0-7][0-9]~msi', $matches[0]) ? stripcslashes($matches[0]) : $matches[0];
        }, $deobfuscated);

        preg_match_all('~(global\s*(\$[\w_]+);)\2\s*=\s*"[^"]+";~msi', $deobfuscated, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $deobfuscated = str_replace($match[0], '', $deobfuscated);
            $deobfuscated = str_replace($match[1], '', $deobfuscated);
        }

        preg_match_all('~\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\'](\w+)[\'"];~msi', $deobfuscated, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $deobfuscated = preg_replace_callback('~\$\{\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]\}~msi', static function ($matches) use ($match) {
                if ($matches[1] !== $match[1]) {
                    return $matches[0];
                }
                return '$' . $match[2];
            }, $deobfuscated);
            $deobfuscated = str_replace($match[0], '', $deobfuscated);
        }

        if (strpos($deobfuscated, '${$') !== false) {
            preg_match_all('~\$\{(\$\w+)\}~msi', $deobfuscated, $matches);
            preg_match_all('~(\$\w+)\s*=\s*["\'](\w+)[\'"];~msi', $deobfuscated, $matches2);
            $replace_to = [];
            foreach ($matches[1] as $k => $match) {
                $index = array_search($match, $matches2[1]);
                if ($index !== false) {
                    $replace_to[] = '$' . $matches2[2][$index];
                } else {
                    unset($matches[0][$k]);
                }
            }
            if (!empty($replace_to)) {
                $deobfuscated = str_replace($matches[0], $replace_to, $deobfuscated);
            }
        }

        if (strpos($deobfuscated, 'chr(')) {
            $deobfuscated = preg_replace_callback('~chr\((\d+)\)~msi', static function ($matches) {
                return "'" . chr($matches[1]) . "'";
            }, $deobfuscated);
        }
        return $deobfuscated;
    }

    /*************************************************************************************************************/
    /*                                Helper functions for individual obfuscators                                */
    /*************************************************************************************************************/

    /**
     * @param $a
     * @param $b
     *
     * @return string
     */
    public static function decodefuncDictVars($a, $b)
    {
        $c = preg_split("//", $a, -1, PREG_SPLIT_NO_EMPTY);
        foreach ($c as $d => $e) {
            $c[$d] = chr(ord($e) + $b);
        }
        $res = implode("", $c);

        return $res;
    }

    /**
     * @param $string
     * @param $amount
     *
     * @return string
     */
    public static function rotencode($string, $amount)
    {
        $key = substr($string, 0, 1);
        if (strlen($string) == 1) {
            return chr(ord($key) + $amount);
        } else {
            return chr(ord($key) + $amount) . self::rotencode(
                    substr($string, 1, strlen($string) - 1),
                    $amount);
        }
    }

    /**
     * @param string $data
     * @param string $key
     *
     * @return string
     */
    public static function decodeEvalFileContentBySize(string $data, string $key): string
    {
        $res = '';
        $key = md5($key) . md5($key . $key);
        $key_len = strlen($key);
        $data_len = strlen($data);
        for ($i = 0; $i < $data_len; $i++) {
            $res .= chr(ord($data[$i]) ^ ord($key[$i % $key_len]));
        }

        return $res;
    }

    /**
     * @param string $key
     * @param string $data
     *
     * @return string
     */
    public static function decodeFuncVars(string $key, string $data): string
    {
        $hakfku = $data;
        $keyLen = strlen($key);
        $dataLen = strlen($hakfku);
        $res = "";
        for ($i = 0; $i < $dataLen;) {
            for ($j = 0; ($j < $keyLen && $i < $dataLen); $j++, $i++) {
                $res .= $hakfku[$i] ^ $key[$j];
            }
        }

        return $res;
    }

    public static function dictionarySampleDecode($string)
    {
        $str1 = substr($string, 0, 5);
        $str2 = substr($string, 7, -7);
        $str3 = substr($string, -5);
        return gzinflate(base64_decode($str1 . $str2 . $str3));
    }

    public static function codelock_dec($codelock_v)
    {
        switch ($codelock_v) {
            case "A":
                $dv = 0;
                break;
            case "B":
                $dv = 1;
                break;
            case "C":
                $dv = 2;
                break;
            case "D":
                $dv = 3;
                break;
            case "E":
                $dv = 4;
                break;
            case "F":
                $dv = 5;
                break;
            case "G":
                $dv = 6;
                break;
            case "H":
                $dv = 7;
                break;
            case "I":
                $dv = 8;
                break;
            case "J":
                $dv = 9;
                break;
            case "K":
                $dv = 10;
                break;
            case "L":
                $dv = 11;
                break;
            case "M":
                $dv = 12;
                break;
            case "N":
                $dv = 13;
                break;
            case "O":
                $dv = 14;
                break;
            case "P":
                $dv = 15;
                break;
            case "Q":
                $dv = 16;
                break;
            case "R":
                $dv = 17;
                break;
            case "S":
                $dv = 18;
                break;
            case "T":
                $dv = 19;
                break;
            case "U":
                $dv = 20;
                break;
            case "V":
                $dv = 21;
                break;
            case "W":
                $dv = 22;
                break;
            case "X":
                $dv = 23;
                break;
            case "Y":
                $dv = 24;
                break;
            case "Z":
                $dv = 25;
                break;
            case "a":
                $dv = 26;
                break;
            case "b":
                $dv = 27;
                break;
            case "c":
                $dv = 28;
                break;
            case "d":
                $dv = 29;
                break;
            case "e":
                $dv = 30;
                break;
            case "f":
                $dv = 31;
                break;
            case "g":
                $dv = 32;
                break;
            case "h":
                $dv = 33;
                break;
            case "i":
                $dv = 34;
                break;
            case "j":
                $dv = 35;
                break;
            case "k":
                $dv = 36;
                break;
            case "l":
                $dv = 37;
                break;
            case "m":
                $dv = 38;
                break;
            case "n":
                $dv = 39;
                break;
            case "o":
                $dv = 40;
                break;
            case "p":
                $dv = 41;
                break;
            case "q":
                $dv = 42;
                break;
            case "r":
                $dv = 43;
                break;
            case "s":
                $dv = 44;
                break;
            case "t":
                $dv = 45;
                break;
            case "u":
                $dv = 46;
                break;
            case "v":
                $dv = 47;
                break;
            case "w":
                $dv = 48;
                break;
            case "x":
                $dv = 49;
                break;
            case "y":
                $dv = 50;
                break;
            case "z":
                $dv = 51;
                break;
            case "0":
                $dv = 52;
                break;
            case "1":
                $dv = 53;
                break;
            case "2":
                $dv = 54;
                break;
            case "3":
                $dv = 55;
                break;
            case "4":
                $dv = 56;
                break;
            case "5":
                $dv = 57;
                break;
            case "6":
                $dv = 58;
                break;
            case "7":
                $dv = 59;
                break;
            case "8":
                $dv = 60;
                break;
            case "9":
                $dv = 61;
                break;
            case "+":
                $dv = 62;
                break;
            case "/":
                $dv = 63;
                break;
            case "=":
                $dv = 64;
                break;
            default:
                $dv = 0;
                break;
        }
        return $dv;
    }

    public static function codelock_run($ciph, $key)
    {
        $m = 0;
        $abc = "";
        for ($i = 0, $iMax = strlen($ciph); $i < $iMax; $i++) {
            $c = substr($ciph, $i, 1);
            $dv = Helpers::codelock_dec($c);
            $dv = ($dv - $m) / 4;
            $fb = decbin($dv);
            while (strlen($fb) < 4) {
                $fb = "0" . $fb;
            }
            $abc = $abc . $fb;
            $m++;
            if ($m > 3) {
                $m = 0;
            }
        }
        $kl = 0;
        $pd = "";
        for ($j = 0, $jMax = strlen($abc); $j < $jMax; $j = $j + 8) {
            $c = substr($abc, $j, 8);
            $k = substr($key, $kl, 1);
            $dc = bindec($c);
            $dc = $dc - strlen($key);
            $c = chr($dc);
            $kl++;
            if ($kl >= strlen($key)) {
                $kl = 0;
            }
            $dc = ord($c) ^ ord($k);
            $p = chr($dc);
            $pd = $pd . $p;
        }
        return $pd;
    }

    public static function codelock_dec_int($codelock_decint_code, $codelock_calc_key)
    {
        if ($codelock_calc_key !== "") {
            $codelock_calc_key = base64_encode($codelock_calc_key);
            $codelock_k1 = substr($codelock_calc_key, 0, 1);
            $codelock_k2 = substr($codelock_calc_key, 1, 1);
            $codelock_k3 = substr($codelock_calc_key, 2, 1);
            $codelock_decint_code = str_replace("$", "$codelock_k1", $codelock_decint_code);
            $codelock_decint_code = str_replace("(", "$codelock_k2", $codelock_decint_code);
            $codelock_decint_code = str_replace(")", "$codelock_k3", $codelock_decint_code);
        }
        $codelock_decint_code = base64_decode($codelock_decint_code);
        return $codelock_decint_code;
    }

    public static function decodeClassDecryptedWithKey(string $data, int $num, string $key): string
    {
        function CTL($start, &$data, &$data_long)
        {
            $n = strlen($data);
            $tmp = unpack('N*', $data);
            $j = $start;
            foreach ($tmp as $value) $data_long[$j++] = $value;
            return $j;
        }

        function LtoC($l)
        {
            return pack('N', $l);
        }

        function add($i1, $i2)
        {
            $result = 0.0;
            foreach (func_get_args() as $value) {
                if (0.0 > $value) {
                    $value -= 1.0 + 0xffffffff;
                }
                $result += $value;
            }
            if (0xffffffff < $result || -0xffffffff > $result) {
                $result = fmod($result, 0xffffffff + 1);
            }
            if (0x7fffffff < $result) {
                $result -= 0xffffffff + 1.0;
            } elseif (-0x80000000 > $result) {
                $result += 0xffffffff + 1.0;
            }
            return $result;
        }

        function delg($y, $z, &$w, &$k, $num)
        {
            $sum = 0xC6EF3720;
            $klhys = 0x9E3779B9;
            $n = $num;
            while ($n-- > 0) {
                $z = add($z, -(add($y << 4 ^ rsLT($y, 5), $y) ^ add($sum, $k[rsLT($sum, 11) & 3])));
                $sum = add($sum, -$klhys);
                $y = add($y, -(add($z << 4 ^ rsLT($z, 5), $z) ^ add($sum, $k[$sum & 3])));
            }
            $w[0] = $y;
            $w[1] = $z;
        }

        function rsLT($integer, $n)
        {
            if (0xffffffff < $integer || -0xffffffff > $integer) {
                $integer = fmod($integer, 0xffffffff + 1);
            }
            if (0x7fffffff < $integer) {
                $integer -= 0xffffffff + 1.0;
            } elseif (-0x80000000 > $integer) {
                $integer += 0xffffffff + 1.0;
            }
            if (0 > $integer) {
                $integer &= 0x7fffffff;
                $integer >>= $n;
                $integer |= 1 << (31 - $n);
            } else {
                $integer >>= $n;
            }
            return $integer;
        }

        function resize(&$data, $size, $nonull = false)
        {
            $n = strlen($data);
            $nmod = $n % $size;
            if (0 == $nmod) $nmod = $size;
            if ($nmod > 0) {
                if ($nonull) {
                    for ($i = $n; $i < $n - $nmod + $size; ++$i) {
                        $data[$i] = $data[$i % $n];
                    }
                } else {
                    for ($i = $n; $i < $n - $nmod + $size; ++$i) {
                        $data[$i] = chr(0);
                    }
                }
            }
            return $n;
        }

        $ncdL = CTL(0, $data, $enc_data_long);
        resize($key, 16, true);
        $n_key_long = CTL(0, $key, $key_long);
        $data = '';
        $w = array(0, 0);
        $j = 0;
        $len = 0;
        $k = array(0, 0, 0, 0);
        $pos = 0;
        for ($i = 0; $i < $ncdL; $i += 2) {
            if ($j + 4 <= $n_key_long) {
                $k[0] = $key_long[$j];
                $k[1] = $key_long[$j + 1];
                $k[2] = $key_long[$j + 2];
                $k[3] = $key_long[$j + 3];
            } else {
                $k[0] = $key_long[$j % $n_key_long];
                $k[1] = $key_long[($j + 1) % $n_key_long];
                $k[2] = $key_long[($j + 2) % $n_key_long];
                $k[3] = $key_long[($j + 3) % $n_key_long];
            }
            $j = ($j + 4) % $n_key_long;
            delg($enc_data_long[$i], $enc_data_long[$i + 1], $w, $k, $num);
            if (0 == $i) {
                $len = $w[0];
                if (4 <= $len) {
                    $data .= LtoC($w[1]);
                } else {
                    $data .= substr(LtoC($w[1]), 0, $len % 4);
                }
            } else {
                $pos = ($i - 1) * 4;
                if ($pos + 4 <= $len) {
                    $data .= LtoC($w[0]);
                    if ($pos + 8 <= $len) {
                        $data .= LtoC($w[1]);
                    } elseif ($pos + 4 < $len) {
                        $data .= substr(LtoC($w[1]), 0, $len % 4);
                    }
                } else {
                    $data .= substr(LtoC($w[0]), 0, $len % 4);
                }
            }
        }
        return $data;
    }

    public static function stripsquoteslashes($str)
    {
        $res = '';
        for ($i = 0, $iMax = strlen($str); $i < $iMax; $i++) {
            if (isset($str[$i+1]) && ($str[$i] == '\\' && ($str[$i+1] == '\\' || $str[$i+1] == '\''))) {
                continue;
            } else {
                $res .= $str[$i];
            }
        }
        return $res;
    }

    public static function decodeFileGetContentsWithFunc($data, $key)
    {
        $out_data = "";

        for ($i = 0; $i < strlen($data);) {
            for ($j = 0; $j < strlen($key) && $i < strlen($data); $j++, $i++) {
                $out_data .= chr(ord($data[$i]) ^ ord($key[$j]));
            }
        }

        return $out_data;
    }

    public static function decrypt_T_func($l)
    {
        $x2 = 256;
        $W2 = 8;
        $cY = [];
        $I3 = 0;
        $C4 = 0;
        for ($bs = 0, $bsMax = strlen($l); $bs < $bsMax; $bs++) {
            $I3 = ($I3 << 8) + ord($l[$bs]);
            $C4 += 8;
            if ($C4 >= $W2) {
                $C4 -= $W2;
                $cY[] = $I3 >> $C4;
                $I3 &= (1 << $C4) - 1;
                $x2++;
                if ($x2 >> $W2) {
                    $W2++;
                }
            }
        }
        $K5 = range("\x0", "\377");
        $UH = '';
        foreach ($cY as $bs => $xd) {
            if (!isset($K5[$xd])) {
                $iU = $Co . $Co[0];
            } else {
                $iU = $K5[$xd];
            }
            $UH .= $iU;
            if ($bs) {
                $K5[] = $Co . $iU[0];
            }
            $Co = $iU;
        }
        return $UH;
    }

    //from sample_16
    public static function someDecoder($str)
    {
        $str = base64_decode($str);
        $TC9A16C47DA8EEE87 = 0;
        $TA7FB8B0A1C0E2E9E = 0;
        $T17D35BB9DF7A47E4 = 0;
        $T65CE9F6823D588A7 = (ord($str[1]) << 8) + ord($str[2]);
        $i = 3;
        $T77605D5F26DD5248 = 0;
        $block = 16;
        $T7C7E72B89B83E235 = "";
        $T43D5686285035C13 = "";
        $len = strlen($str);

        $T6BBC58A3B5B11DC4 = 0;

        for (; $i < $len;) {
            if ($block == 0) {
                $T65CE9F6823D588A7 = (ord($str[$i++]) << 8);
                $T65CE9F6823D588A7 += ord($str[$i++]);
                $block = 16;
            }
            if ($T65CE9F6823D588A7 & 0x8000) {
                $TC9A16C47DA8EEE87 = (ord($str[$i++]) << 4);
                $TC9A16C47DA8EEE87 += (ord($str[$i]) >> 4);
                if ($TC9A16C47DA8EEE87) {
                    $TA7FB8B0A1C0E2E9E = (ord($str[$i++]) & 0x0F) + 3;
                    for ($T17D35BB9DF7A47E4 = 0; $T17D35BB9DF7A47E4 < $TA7FB8B0A1C0E2E9E; $T17D35BB9DF7A47E4++) {
                        $T7C7E72B89B83E235[$T77605D5F26DD5248 + $T17D35BB9DF7A47E4] =
                            $T7C7E72B89B83E235[$T77605D5F26DD5248 - $TC9A16C47DA8EEE87 + $T17D35BB9DF7A47E4];
                    }
                    $T77605D5F26DD5248 += $TA7FB8B0A1C0E2E9E;
                } else {
                    $TA7FB8B0A1C0E2E9E = (ord($str[$i++]) << 8);
                    $TA7FB8B0A1C0E2E9E += ord($str[$i++]) + 16;
                    for ($T17D35BB9DF7A47E4 = 0; $T17D35BB9DF7A47E4 < $TA7FB8B0A1C0E2E9E;
                         $T7C7E72B89B83E235[$T77605D5F26DD5248 + $T17D35BB9DF7A47E4++] = $str[$i]) {
                    }
                    $i++;
                    $T77605D5F26DD5248 += $TA7FB8B0A1C0E2E9E;
                }
            } else {
                $T7C7E72B89B83E235[$T77605D5F26DD5248++] = $str[$i++];
            }
            $T65CE9F6823D588A7 <<= 1;
            $block--;
            if ($i == $len) {
                $T43D5686285035C13 = $T7C7E72B89B83E235;
                if (is_array($T43D5686285035C13)) {
                    $T43D5686285035C13 = implode($T43D5686285035C13);
                }
                $T43D5686285035C13 = "?" . ">" . $T43D5686285035C13;
                return $T43D5686285035C13;
            }
        }
    }

    public static function someDecoder2($WWAcmoxRAZq, $sBtUiFZaz)   //sample_05
    {
        $JYekrRTYM = str_rot13(gzinflate(str_rot13(base64_decode('y8svKCwqLiktK6+orFdZV0FWWljPyMzKzsmNNzQyNjE1M7ewNAAA'))));
        if ($WWAcmoxRAZq == 'asedferg456789034689gd') {
            $cEerbvwKPI = $JYekrRTYM[18] . $JYekrRTYM[19] . $JYekrRTYM[17] . $JYekrRTYM[17] . $JYekrRTYM[4] . $JYekrRTYM[21];
            return Helpers::convertToSafeFunc($cEerbvwKPI) ? $cEerbvwKPI($sBtUiFZaz) : '';
        } elseif ($WWAcmoxRAZq == 'zfcxdrtgyu678954ftyuip') {
            $JWTDeUKphI = $JYekrRTYM[1] . $JYekrRTYM[0] . $JYekrRTYM[18] . $JYekrRTYM[4] . $JYekrRTYM[32] .
                $JYekrRTYM[30] . $JYekrRTYM[26] . $JYekrRTYM[3] . $JYekrRTYM[4] . $JYekrRTYM[2] . $JYekrRTYM[14] .
                $JYekrRTYM[3] . $JYekrRTYM[4];
            return Helpers::convertToSafeFunc($JWTDeUKphI) ? $JWTDeUKphI($sBtUiFZaz) : '';
        } elseif ($WWAcmoxRAZq == 'gyurt456cdfewqzswexcd7890df') {
            $rezmMBMev = $JYekrRTYM[6] . $JYekrRTYM[25] . $JYekrRTYM[8] . $JYekrRTYM[13] . $JYekrRTYM[5] . $JYekrRTYM[11] . $JYekrRTYM[0] . $JYekrRTYM[19] . $JYekrRTYM[4];
            return Helpers::convertToSafeFunc($rezmMBMev) ? $rezmMBMev($sBtUiFZaz) : '';
        } elseif ($WWAcmoxRAZq == 'zcdfer45dferrttuihvs4321890mj') {
            $WbbQXOQbH = $JYekrRTYM[18] . $JYekrRTYM[19] . $JYekrRTYM[17] . $JYekrRTYM[26] . $JYekrRTYM[17] . $JYekrRTYM[14] . $JYekrRTYM[19] . $JYekrRTYM[27] . $JYekrRTYM[29];
            return Helpers::convertToSafeFunc($WbbQXOQbH) ? $WbbQXOQbH($sBtUiFZaz) : '';
        } elseif ($WWAcmoxRAZq == 'zsedrtre4565fbghgrtyrssdxv456') {
            $jPnPLPZcMHgH = $JYekrRTYM[2] . $JYekrRTYM[14] . $JYekrRTYM[13] . $JYekrRTYM[21] . $JYekrRTYM[4] . $JYekrRTYM[17] . $JYekrRTYM[19] . $JYekrRTYM[26] . $JYekrRTYM[20] . $JYekrRTYM[20] . $JYekrRTYM[3] . $JYekrRTYM[4] . $JYekrRTYM[2] . $JYekrRTYM[14] . $JYekrRTYM[3] . $JYekrRTYM[4];
            return Helpers::convertToSafeFunc($jPnPLPZcMHgH) ? $jPnPLPZcMHgH($sBtUiFZaz) : '';
        }
    }

    public static function someDecoder3($str)
    {
        $l = base64_decode($str);
        $lllllll = 0;
        $lllll = 3;
        $llllll = (ord($l[1]) << 8) + ord($l[2]);
        $lllllllll = 16;
        $llllllll = [];
        for ($lllllMax = strlen($l); $lllll < $lllllMax;) {
            if ($lllllllll == 0) {
                $llllll = (ord($l[$lllll++]) << 8);
                $llllll+= ord($l[$lllll++]);
                $lllllllll = 16;
            }
            if ($llllll & 0x8000) {
                $lll = (ord($l[$lllll++]) << 4);
                $lll+= (ord($l[$lllll]) >> 4);
                if ($lll) {
                    $ll = (ord($l[$lllll++]) & 0x0f) + 3;
                    for ($llll = 0;$llll < $ll;$llll++) $llllllll[$lllllll + $llll] = $llllllll[$lllllll - $lll + $llll];
                    $lllllll+= $ll;
                } else {
                    $ll = (ord($l[$lllll++]) << 8);
                    $ll+= ord($l[$lllll++]) + 16;
                    for ($llll = 0;$llll < $ll;$llllllll[$lllllll + $llll++] = ord($l[$lllll]));
                    $lllll++;
                    $lllllll+= $ll;
                }
            } else {
                $llllllll[$lllllll++] = ord($l[$lllll++]);
            }
            $llllll <<= 1;
            $lllllllll--;
        }
        $lllll = 0;
        $lllllllll="?".chr(62);
        $llllllllll = "";
        for (;$lllll < $lllllll;) {
            $llllllllll.= chr($llllllll[$lllll++] ^ 0x07);
        }
        $lllllllll.=$llllllllll.chr(60)."?";
        return $lllllllll;
    }

    public static function PHPJiaMi_decoder($str, $md5, $rand, $lower_range = '')
    {
        $md5_xor = md5($md5);
        $lower_range = !$lower_range ? ord($rand) : $lower_range;
        $layer1 = '';
        for ($i=0, $iMax = strlen($str); $i < $iMax; $i++) {
            $layer1 .= ord($str[$i]) < 245 ? ((ord($str[$i]) > $lower_range && ord($str[$i]) < 245) ? chr(ord($str[$i]) / 2) : $str[$i]) : '';
        }
        $layer1 = base64_decode($layer1);
        $result = '';
        $j = $len_md5_xor = strlen($md5_xor);
        for ($i=0, $iMax = strlen($layer1); $i < $iMax; $i++) {
            $j = $j ? $j : $len_md5_xor;
            $j--;
            $result .= $layer1[$i] ^ $md5_xor[$j];
        }
        return $result;
    }

    public static function someDecoder4($ae, $key)
    {
        $at = [];
        for ($i = 0, $iMax = strlen($key); $i < $iMax; $i++) {
            if ((int)$key[$i] > 0) {
                $at[$i] = $key[$i];
            }
        }
        $at = array_values($at);
        $str = "";
        for ($i = 0, $iMax = count($ae); $i < $iMax; $i++) {
            if ($i < count($ae) - 1) {
                $str .= str_replace(md5($at[$i]), "", $ae[$i]);
            } else {
                $str .= $ae[$i];
            }
        }
        return $str;
    }

    public static function OELoveDecoder($arg1, $arg2 = '')
    {
        if (empty($arg1)) {
            return '';
        }
        $arg1 = base64_decode($arg1);
        if ($arg2 == '') return ~$arg1;
        //if ($arg2 == '-1') @271552362217();
        $len = strlen($arg1);
        $arg2 = str_pad($arg2, $len, $arg2);
        return $arg2 ^ $arg1;
    }

    public static function aanKFMDigitsDecode($digits)
    {
        $res = '';
        $len = ceil(strlen($digits) / 3) * 3;
        $cipher = str_pad($digits, $len, '0', STR_PAD_LEFT);
        for ($i = 0; $i < (strlen($cipher) / 3);$i++) {
            $res .= chr(substr($cipher, $i * 3, 3));
        }
        return $res;
    }

    public static function obf20200414_1_decrypt($data, $key)
    {
        $key = md5($key);
        $x = 0;
        $data = base64_decode($data);
        $len = strlen($data);
        $l = strlen($key);
        $char = '';
        for ($i = 0; $i < $len; $i++) {
            if ($x === $l) {
                $x = 0;
            }
            $char .= substr($key, $x, 1);
            $x++;
        }
        $str = '';
        for ($i = 0; $i < $len; $i++) {
            if (ord(substr($data, $i, 1)) < ord(substr($char, $i, 1))) {
                $str .= chr((ord(substr($data, $i, 1)) + 256) - ord(substr($char, $i, 1)));
            } else {
                $str .= chr(ord(substr($data, $i, 1)) - ord(substr($char, $i, 1)));
            }
        }
        return $str;
    }

    public static function Xtea_decrypt($text, $key)
    {
        $_key = '';
        $cbc = 1;

        if(is_array($key)) {
            $_key = $key;
        } else if(isset($key) && !empty($key)) {
            $_key = self::_str2long(str_pad($key, 16, $key));
        } else {
            $_key = [0, 0, 0, 0];
        }

        $plain = [];
        $cipher = self::_str2long(base64_decode($text));

        if($cbc == 1) {
            $i = 2;
        } else {
            $i = 0;
        }

        for ($i, $iMax = count($cipher); $i < $iMax; $i += 2) {
            $return = self::block_decrypt($cipher[$i], $cipher[$i+1], $_key);
            if($cbc == 1) {
                $plain[] = [$return[0] ^ $cipher[$i - 2], $return[1] ^ $cipher[$i - 1]];
            } else {
                $plain[] = $return;
            }
        }

        $output = "";
        for($i = 0, $iMax = count($plain); $i < $iMax; $i++) {
            $output .= self::_long2str($plain[$i][0]);
            $output .= self::_long2str($plain[$i][1]);
        }

        return $output;
    }

    public static function getDecryptKeyForTinkleShell($size)
    {
        $bx = md5(base64_encode($size));
        $len = strlen($bx);
        $arr = [];
        for ($i = 0; $i < $len; $i++) {
            $arr[] = substr($bx, $i, 1);
        }
        $arr = array_unique($arr);
        $newstr = "";
        foreach ($arr as $k => $v) {
            $newstr .= $v;
        }
        if (strlen($newstr) < 9) {
            if (strpos($newstr, 'A') === false) {
                $newstr .= 'A';
            }
            if (strpos($newstr, 'B') === false) {
                $newstr .= 'B';
            }
            if (strpos($newstr, 'C') === false) {
                $newstr .= 'C';
            }
            if (strpos($newstr, 'D') === false) {
                $newstr .= 'D';
            }
            if (strpos($newstr, 'E') === false) {
                $newstr .= 'E';
            }
            if (strpos($newstr, 'F') === false) {
                $newstr .= 'F';
            }
            if (strpos($newstr, 'G') === false) {
                $newstr .= 'G';
            }
        }

        return strtoupper($newstr);
    }

    /**
     * For 4 args
     * @param array $arr
     *
     * @return string
     */
    public static function decodeEvalCreateFunc_1(array $arr) : string
    {
        $args = $arr;

        for ($i = 0; $i < 4; $i++) {
            for ($j = 0, $jMax = strlen($args[$i]); $j < $jMax; $j++) {
                $args[$i][$j] = chr(ord($args[$i][$j]) - ($i ? $args[$j xor $j] : 1));
            }
            if ($i === 2 && self::convertToSafeFunc($args[1]) && self::convertToSafeFunc($args[2])) {
                $args[3] = @$args[1](@$args[2]($args[3]));
            }
        }

        return $args[3];
    }

    /**
     * For 3 args
     * @param array $arr
     *
     * @return string
     */
    public static function decodeEvalCreateFunc_2(array $arr) : string
    {
        $args = $arr;

        for ($i = 0; $i < 3; $i++) {
            for ($j = 0, $jMax = strlen($args[$i]); $j < $jMax; $j++) {
                $args[$i][$j] = chr(ord($args[$i][$j]) - 1);
            }
            if ($i === 1 && self::convertToSafeFunc($args[0]) && self::convertToSafeFunc($args[1])) {
                $args[2] = @$args[0](@$args[1]($args[2]));
            }
        }

        return $args[2];
    }

    public static function decodeACharCustom($encoded)
    {
        $result = '';
        $i = 0;
        $len = strlen($encoded);
        while ($i < $len) {
            if ($encoded[$i] === ' ') {
                $result .= ' ';
            } else if ($encoded[$i] === '!') {
                $result .= chr((ord($encoded[$i + 1]) - ord('A')) * 16 + (ord($encoded[$i + 2]) - ord('a')));
                $i += 2;
            } else {
                $result .= chr (ord($encoded[$i]) + 1);
            }
            $i++;
        }
        return $result;
    }

    public static function joomlaInjectDecoder($params, $op, $delta)
    {
        $params = explode(',', $params);
        $params = array_reverse($params);
        for ($i = 1, $iMax = count($params); $i < $iMax; $i++) {
            if ($i !== 0 ) {
                $params[$i] = substr($params[$i], 1, -1);
            }
            for ($j = 0, $jMax = strlen($params[$i]); $j < $jMax; $j++) {
                $tmp = ord($params[$i][$j]);
                if ($op === '-') {
                    $tmp = $tmp - $delta;

                } else if ($op === '+') {
                    $tmp = $tmp + $delta;
                }
                $params[$i][$j] = chr($tmp);
            }
            if ($i === 0) {
                break;
            }
            if (self::convertToSafeFunc($params[$i])) {
                $params[0] = $params[$i]($params[0]);
            }
            if ($i === $iMax - 1) {
                $i = -1;
            }
        }
        return $params[0];
    }

    public static function deobfuscatorIO_string($string, $key)
    {
        $m = [];
        $n = 0;
        $p = '';
        $string = base64_decode($string);
        for ($i = 0, $iMax = strlen($string); $i < $iMax; $i++) {
            if ($string[$i] === "\xC3") {
                $inc = 64;
                continue;
            } else if ($string[$i] === "\xC2") {
                continue;
            }
            $p .= chr(ord($string[$i]) + $inc);
            $inc = 0;
        }
        $string = $p;
        $p = '';
        for ($i = 0; $i < 256; $i++) {
            $m[$i] = $i;
        }
        for ($i = 0; $i < 256; $i++) {
            $n = ($n + $m[$i] + ord($key[$i % strlen($key)])) % 256;
            $o = $m[$i];
            $m[$i] = $m[$n];
            $m[$n] = $o;
        }
        $r = 0;
        $n = 0;
        for ($i = 0, $iMax = strlen($string); $i < $iMax; $i++) {
            $r = ($r + 1) % 256;
            $n = ($n + $m[$r]) % 256;
            $o = $m[$r];
            $m[$r] = $m[$n];
            $m[$n] = $o;
            $p .= chr(ord($string[$i]) ^ $m[($m[$r] + $m[$n]) % 256]);
        }
        return $p;
    }

    public static function decodeEvalFuncBinary($input)
    {
        if (empty($input)) {
            return;
        }
        $keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        $chr1 = $chr2 = $chr3 = "";
        $enc1 = $enc2 = $enc3 = $enc4 = "";
        $i = 0;
        $output = "";
        $input = preg_replace("[^A-Za-z0-9\+\/\=]", "", $input);
        do {
            $enc1 = strpos($keyStr, substr($input, $i++, 1));
            $enc2 = strpos($keyStr, substr($input, $i++, 1));
            $enc3 = strpos($keyStr, substr($input, $i++, 1));
            $enc4 = strpos($keyStr, substr($input, $i++, 1));
            $chr1 = ($enc1 << 2) | ($enc2 >> 4);
            $chr2 = (($enc2 & 15) << 4) | ($enc3 >> 2);
            $chr3 = (($enc3 & 3) << 6) | $enc4;
            $output .= chr($chr1);
            if ($enc3 !== 64) {
                $output .= chr($chr2);
            }
            if ($enc4 !== 64) {
                $output .= chr($chr3);
            }
            $chr1 = $chr2 = $chr3 = "";
            $enc1 = $enc2 = $enc3 = $enc4 = "";
        } while ($i < strlen($input));

        return $output;
    }

    public static function jsPackerUnbaser($int, $radix)
    {
        if ($int < $radix) {
            $ret = '';
        } else {
            $ret = self::jsPackerUnbaser((int)($int / $radix), $radix);
        }

        if (($int = $int % $radix) > 35) {
            $ret .= chr($int + 29);
        } else {
            $ret .= base_convert((string)$int, 10, 36);
        }
        return $ret;
    }

    public static function jsObjectDecodeIndexToString($int)
    {
        $ret = base_convert((string)$int, 10, 36);
        $ret = preg_replace_callback('~[0-9]~', function ($m) {
            return chr((int)$m[0] + 65);
        }, $ret);
        return $ret;
    }

    public static function jsObjectStringDecoder($r, $t, $encoded)
    {
        $ret = '';
        $i = 1;
        for ($f = 0, $fMax = strlen($encoded); $f < $fMax; $f++) {
            $o = strpos($r, $encoded[$f]);
            if (in_array($encoded[$f], $t)) {
                $i = 0;
            }
            if ($o !== false) {
                $ret .= chr($i * strlen($r) + $o);
                $i = 1;
            }
        }
        return $ret;
    }

    public static function utfCharVarsFuncEvalVarDecoder($argOne, $argTwo = '')
    {
        $argOne = base64_decode($argOne);
        if (empty($argOne)) {
            return '';
        }
        if ($argTwo == '') {
            return ~$argOne;
        } else {
            //$temp   = $globalVar['¾”Ã‰Å”—˜']($argOne);//strlen
            //$argTwo = $globalVar['ÊƒÑÇ»µ½Èªº']($argTwo, $temp, $argTwo); //str_pad
            $temp   = strlen($argOne);//strlen
            $argTwo = str_pad($argTwo, $temp, $argTwo); //str_pad
            return $argOne ^ $argTwo;
        }
    }

    public static function utfCharVarsFuncEvalVarCollector($globalVarName, $funcName, &$str, &$vars = []): array
    {
        $varsMatchesRegex = '~\\' . $globalVarName . '\[\'([^\']+)\'\]\s?=\s?' . $funcName . '\(\'([^\']+)\',\'([^\']*)\'\);~msi';
        preg_match_all($varsMatchesRegex, $str, $varsMatches, PREG_SET_ORDER);

        foreach ($varsMatches as $varsMatch) {
            $vars[$varsMatch[1]] = self::utfCharVarsFuncEvalVarDecoder($varsMatch[2], $varsMatch[3]);
            $str = str_replace($varsMatch[0], '', $str);
        }

        return $vars;
    }

    public static function utfCharVarsFuncEvalCodeDecoder(&$str, &$vars, $globalVarName, $funcName): string
    {
        $vars = Helpers::utfCharVarsFuncEvalVarCollector($globalVarName, $funcName, $str, $vars);
        foreach ($vars as $name => $val) {
            $str = str_replace($globalVarName . '[\'' . $name . '\'](', $val . '(', $str);
        }

        return $str;
    }

    private static function block_decrypt($y, $z, $key)
    {
        $delta = 0x9e3779b9;
        $sum = 0xC6EF3720;
        $n = 32;

        for ($i = 0; $i < 32; $i++) {
            $z = self::_add($z, -(self::_add($y << 4 ^ self::_rshift($y, 5), $y)
                ^ self::_add($sum, $key[self::_rshift($sum, 11) & 3])));
            $sum = self::_add($sum, -$delta);
            $y = self::_add($y, -(self::_add($z << 4 ^ self::_rshift($z, 5), $z)
                ^ self::_add($sum, $key[$sum & 3])));

        }
        return [$y, $z];
    }

    private static function _rshift($integer, $n)
    {
        if (0xffffffff < $integer || -0xffffffff > $integer) {
            $integer = fmod($integer, 0xffffffff + 1);
        }

        if (0x7fffffff < $integer) {
            $integer -= 0xffffffff + 1.0;
        } else if (-0x80000000 > $integer) {
            $integer += 0xffffffff + 1.0;
        }

        if (0 > $integer) {
            $integer &= 0x7fffffff;
            $integer >>= $n;
            $integer |= 1 << (31 - $n);
        } else {
            $integer >>= $n;
        }
        return $integer;
    }

    private static function _add($i1, $i2)
    {
        $result = 0.0;

        foreach (func_get_args() as $value) {
            if (0.0 > $value) {
                $value -= 1.0 + 0xffffffff;
            }
            $result += $value;
        }

        if (0xffffffff < $result || -0xffffffff > $result) {
            $result = fmod($result, 0xffffffff + 1);
        }

        if (0x7fffffff < $result) {
            $result -= 0xffffffff + 1.0;
        } else if (-0x80000000 > $result) {
            $result += 0xffffffff + 1.0;
        }
        return $result;
    }

    private static function _str2long($data)
    {
        $tmp = unpack('N*', $data);
        $data_long = [];
        $j = 0;

        foreach ($tmp as $value) $data_long[$j++] = $value;
        return $data_long;
    }

    private static function _long2str($l){
        return pack('N', $l);
    }

}

/**
 * Class for calculating mathematical functions, examples can be found here tests/deobfuscator/CheckDeobfuscationHelpersTest.php
 */
class MathCalc {
    const ELEMENT_TYPE_OPERATION            = 'operation';
    const ELEMENT_TYPE_NUMBER               = 'number';
    const ELEMENT_TYPE_SIMPLE_PARENTHESES   = 'simple_parentheses';

    const ELEMENT       = 'element';
    const ELEMENT_TYPE  = 'type';

    const REGEXP_VALUE      = '[0-9]*\.[0-9]+|[1-9][0-9]*|0(?:x[\da-f]+|b[01]+|[0-7]+)|0';
    const REGEXP_OPERATION  = '\+|\-|/|\*\*|\*|%|&|\||\^|\~|<<|>>';
    const REGEXP_VALUE_SIGN = '\-|\+';

    private static $math_operations_order = [];

    public static function calcRawString($raw_string, $max_iterations = 10)
    {
        self::loadMathOperationsOrder();

        $iterations = 0;
        do {
            $old_string = $raw_string;
            $raw_string = self::calcRawStringOnePassWithParentheses($raw_string);
            $raw_string = FuncCalc::calcFuncInRawStringOnePassWithParentheses($raw_string);
            if ($raw_string == $old_string) {
                break;
            }
            $iterations++;
        } while($iterations < $max_iterations);

        $iterations = 0;
        do {
            $old_string = $raw_string;
            $raw_string = self::calcRawStringOnePassWithoutParentheses($raw_string);
            if ($raw_string == $old_string) {
                break;
            }
            $iterations++;
        } while($iterations < $max_iterations);

        return $raw_string;
    }

    ////////////////////////////////////////////////////////////////////////////

    private static function calcRawStringOnePassWithParentheses($raw_string)
    {
        self::loadMathOperationsOrder();
        $regexp_find_simple_math_operations = '('
            . '\s*(?:\(\s*[+-]?\s*(?:' . self::REGEXP_VALUE . ')\s*\))\s*'
            . '|'
            . '\s*(?:' . self::REGEXP_VALUE . ')\s*'
            . '|'
            . '\s*(?:' . self::REGEXP_OPERATION . ')\s*'
            . ')+';
        $regexp_find_math_operations_inside_brackets    = '\(' . $regexp_find_simple_math_operations . '\)';
        return preg_replace_callback('~' . $regexp_find_math_operations_inside_brackets . '~mis', function($matches) {
            $original = $matches[0];
            $math_string = substr($original, 1, strlen($original) - 2);
            if (self::haveOnlyValue($math_string) || self::haveOnlyOperation($math_string)) {
                return $original;
            }
            try {
                $result = self::calcSimpleMath($math_string);
            }
            catch (\Exception $e) {
                return $original;
            }
            return '(' . $result . ')';
        }, $raw_string);
    }

    private static function calcRawStringOnePassWithoutParentheses($raw_string)
    {
        self::loadMathOperationsOrder();
        $regexp_find_simple_math_operations = '(?:'
            . '\s*?(?:\(\s*[+-]?\s*(?:' . self::REGEXP_VALUE . ')\s*\))\s*?'
            . '|'
            . '\s*?(?:' . self::REGEXP_VALUE . ')\s*?'
            . '|'
            . '\s*?(?:' . self::REGEXP_OPERATION . ')\s*?'
            . ')+';
        return preg_replace_callback('~(\s*)(' . $regexp_find_simple_math_operations . ')(\s*)~mis', function($matches){
            $begin          = $matches[1];
            $math_string    = $matches[2];
            $end            = $matches[3];
            $original       = $begin . $math_string . $end;

            if (self::haveOnlyValueWithParentheses($math_string) || self::haveOnlyOperationWithParentheses($math_string)) {
                return $original;
            }
            if (self::haveOnlyValue($math_string)) {
                return $original;
            }
            if (self::haveOnlyOperation($math_string)) {
                return $original;
            }

            try {
                $result = self::calcSimpleMath($math_string);
            }
            catch (\Exception $e) {
                return $original;
            }

            return $begin . $result . $end;
        }, $raw_string);
    }

    private static function loadMathOperationsOrder()
    {
        if (!empty(self::$math_operations_order)) {
            return;
        }

        self::$math_operations_order = [
            [
                '**' => [
                    'elements' => [-1, +1],
                    'func' => function($a, $b) {
                        return $a ** $b;
                    },
                ],
            ],
            [
                '~' => [
                    'elements' => [+1],
                    'func' => function($a) {
                        return ~$a;
                    },
                ],
            ],
            [
                '*' => [
                    'elements' => [-1, +1],
                    'func' => function($a, $b) {
                        return $a * $b;
                    },
                ],
                '/' => [
                    'elements' => [-1, +1],
                    'func' => function($a, $b) {
                        if ($b == 0) {
                            throw new Exception('Division by zero');
                        }
                        return $a / $b;
                    },
                ],
                '%' => [
                    'elements' => [-1, +1],
                    'func' => function($a, $b) {
                        if ($b == 0) {
                            throw new Exception('Division by zero');
                        }
                        return $a % $b;
                    },
                ],
            ],
            [
                '+' => [
                    'elements' => [-1, +1],
                    'func' => function($a, $b) {
                        return $a + $b;
                    },
                ],
                '-' => [
                    'elements' => [-1, +1],
                    'func' => function($a, $b) {
                        return $a - $b;
                    },
                ],
            ],
            [
                '<<' => [
                    'elements' => [-1, +1],
                    'func' => function($a, $b) {
                        return $a << $b;
                    },
                ],
                '>>' => [
                    'elements' => [-1, +1],
                    'func' => function($a, $b) {
                        return $a >> $b;
                    },
                ],
            ],
            [
                '&' => [
                    'elements' => [-1, +1],
                    'func' => function($a, $b) {
                        return $a & $b;
                    },
                ],
            ],
            [
                '^' => [
                    'elements' => [-1, +1],
                    'func' => function($a, $b) {
                        return $a ^ $b;
                    },
                ],
            ],
            [
                '|' => [
                    'elements' => [-1, +1],
                    'func' => function($a, $b) {
                        return $a | $b;
                    },
                ],
            ],
        ];
    }

    private static function haveOnlyValue($string)
    {
        return preg_match('~^\s*[+-]?\s*(?:' . self::REGEXP_VALUE . ')\s*$~mis', $string);
    }

    private static function haveOnlyOperation($string)
    {
        return preg_match('~^(\s*(?:' . self::REGEXP_OPERATION . ')\s*)+$~mis', $string);
    }

    private static function haveOnlyValueWithParentheses($string)
    {
        return preg_match('~^\s*(?:\(\s*[+-]?\s*(?:' . self::REGEXP_VALUE . ')\s*\))\s*$~mis', $string);
    }

    private static function haveOnlyOperationWithParentheses($string)
    {
        return preg_match('~^\s*(?:\(\s*(?:' . self::REGEXP_OPERATION . ')\s*\))\s*$~mis', $string);
    }

    private static function calcSimpleMath($string, $max_iterations = 30)
    {

        $input_string = $string;
        $input_string = str_replace(' ', '', $input_string);
        $input_string = str_replace(['+-', '-+'], '-', $input_string);
        $input_string = str_replace(['--', '++'], '+', $input_string);

        $regexp_find_simple_math_operations = '('
                . '(?<' . self::ELEMENT_TYPE_SIMPLE_PARENTHESES . '>\(\s*[+-]?\s*(?:' . self::REGEXP_VALUE . ')\s*\))\s*'
                . '|'
                . '(?<' . self::ELEMENT_TYPE_NUMBER . '>' . self::REGEXP_VALUE . ')'
                . '|'
                . '(?<' . self::ELEMENT_TYPE_OPERATION . '>' . self::REGEXP_OPERATION . ')'
                . ')';
        if (!preg_match_all('~'.$regexp_find_simple_math_operations.'~mis', $input_string, $matches)) {
            return $string;
        }

        $math_array = [];
        foreach ($matches[0] as $index => $element) {
            if ($element === $matches[self::ELEMENT_TYPE_OPERATION][$index]) {
                $type = self::ELEMENT_TYPE_OPERATION;
            }
            elseif ($element === $matches[self::ELEMENT_TYPE_NUMBER][$index]) {
                $type       = self::ELEMENT_TYPE_NUMBER;
                $k = $element;
                $element    = self::convertNum($element);
            }
            elseif ($element === $matches[self::ELEMENT_TYPE_SIMPLE_PARENTHESES][$index]) {
                $type = self::ELEMENT_TYPE_NUMBER;
                $element = self::convertNum(trim($element, '()'));
            }
            else {
                throw new Exception();
            }

            $math_array[] = [
                self::ELEMENT       => $element,
                self::ELEMENT_TYPE  => $type,
            ];
        }

        if ($math_array[0][self::ELEMENT_TYPE] == self::ELEMENT_TYPE_OPERATION
            && $math_array[0][self::ELEMENT] == '-'
            && $math_array[1][self::ELEMENT_TYPE] == self::ELEMENT_TYPE_NUMBER
        ) {
            unset($math_array[0]);
            $math_array[1][self::ELEMENT] *= -1;
            $math_array = array_values($math_array);
        }

        $changed = false;
        foreach (self::$math_operations_order as $level => $operations) {
            $iterations = 0;
            do {
                $interrupted = false;
                foreach ($math_array as $index => &$element) {
                    if ($element[self::ELEMENT_TYPE] != self::ELEMENT_TYPE_OPERATION) {
                        continue;
                    }

                    if (!isset($operations[$element[self::ELEMENT]])) {
                        continue;
                    }

                    $func_params    = $operations[$element[self::ELEMENT]];
                    $val1_offset    = $func_params['elements'][0];
                    $val2_offset    = isset($func_params['elements'][1]) ? $func_params['elements'][1] : null;
                    $val1_index     = $index + $val1_offset;
                    $val2_index     = $index + $val2_offset;

                    if(!isset($math_array[$val1_index])) {
                        continue;
                    }

                    $val1 = $math_array[$val1_index][self::ELEMENT];

                    if (is_null($val2_offset)) {
                        try {
                            $result = $func_params['func']($val1);
                        }
                        catch (\Exception $e) {
                            continue;
                        }
                        $element[self::ELEMENT] = $result;
                    }
                    else {
                        if (!isset($math_array[$val2_index])) {
                            continue;
                        }
                        $val2 = $math_array[$val2_index][self::ELEMENT];

                        try {
                            $result = $func_params['func']($val1, $val2);
                        }
                        catch (\Exception $e) {
                            throw new \Exception('');
                        }
                        $element[self::ELEMENT] = $result;
                    }
                    $element[self::ELEMENT_TYPE] = self::ELEMENT_TYPE_NUMBER;

                    unset($math_array[$val1_index]);
                    if (!is_null($val2_offset)) {
                        unset($math_array[$val2_index]);
                    }
                    $changed        = true;
                    $interrupted    = true;
                    break;
                }
                unset($element);
                $math_array = array_values($math_array);
                $iterations++;
                if ($iterations >= $max_iterations) {
                    return $string;
                }
            } while ($interrupted);
        }

        if (!$changed) {
            return $string;
        }

        $return_value = '';
        foreach ($math_array as $element) {
            $return_value .= $element[self::ELEMENT];
        }
        return $return_value;
    }

    private static function convertNum(string $string)
    {
        if(stripos($string, '0x') === 0) {
            return (float)hexdec($string);
        }
        elseif(stripos($string, '0b') === 0) {
            return (float)bindec($string);
        }
        elseif(stripos($string, '0.') === 0) {
            return (float)$string;
        }
        elseif ($string !== '0' && substr($string, 0, 1) == '0') {
            return (float)octdec($string);
        }
        return (float)$string;
    }
}

/**
 * The class is auxiliary for MathCalc, calculates certain specific mathematical functions with explicit values
 */
class FuncCalc {
    private static $functions = [];

    private static $functions_regexp = '';

    public static function calcFuncInRawStringOnePassWithParentheses($raw_string)
    {
        if (empty(self::$functions)) {
            self::loadFunctions();
        }

        $regexp_find_functions = '(?:'
                . '('.self::$functions_regexp.')'
                . '\s*\(([^)]+)\)'
                . ')+';

        return preg_replace_callback('~' . $regexp_find_functions . '~mis', function($matches) {
            $name   = $matches[1];
            $params = $matches[2];
            return self::calcFunction($name, $params);
        }, $raw_string);
    }

    ////////////////////////////////////////////////////////////////////////////

    private static function calcFunction($name, $params) {
        $result             = "$name($params)";//safely
        $name_lower         = strtolower($name);
        $function_otions    = isset(self::$functions[$name_lower]) ? self::$functions[$name_lower] : false;
        if (!$function_otions) {
            return $result;
        }

        $params_array = explode(',', $params);
        $params_array = array_map('trim', $params_array);

        try {
            return $function_otions['func'](...$params_array);//safely
        } catch (Exception $ex) {
            return $result;
        }
    }

    private static function loadFunctions()
    {
        self::$functions = [
            'min' => [
                'func' => function(...$a) {
                    return min($a);
                },
            ],
            'max' => [
                'func' => function(...$a) {
                    return max($a);
                },
            ],
            'round' => [
                'func' => function($a, $b = 0) {
                    return round($a, $b);
                },
            ],
            'abs' => [
                'func' => function($a) {
                    return abs($a);
                },
            ],
        ];
        self::$functions_regexp = implode('|', array_keys(self::$functions));
    }

}




///////////////////////////////////////////////////////////////////////////

function parseArgs($argv)
{
    array_shift($argv);
    $o = [];
    foreach ($argv as $a) {
        if (substr($a, 0, 2) == '--') {
            $eq = strpos($a, '=');
            if ($eq !== false) {
                $o[substr($a, 2, $eq - 2)] = substr($a, $eq + 1);
            } else {
                $k = substr($a, 2);
                if (!isset($o[$k])) {
                    $o[$k] = true;
                }
            }
        } else {
            if (strpos($a, '-') === 0) {
                if (substr($a, 2, 1) === '=') {
                    $o[substr($a, 1, 1)] = substr($a, 3);
                } else {
                    foreach (str_split(substr($a, 1)) as $k) {
                        if (!isset($o[$k])) {
                            $o[$k] = true;
                        }
                    }
                }
            } else {
                $o[] = $a;
            }
        }
    }
    return $o;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////
// cli handler
if (!defined('AIBOLIT_START_TIME') && !defined('PROCU_CLEAN_DB') && @strpos(__FILE__, @$argv[0])!==false) {
    set_time_limit(0);
    ini_set('max_execution_time', '900000');
    ini_set('realpath_cache_size', '16M');
    ini_set('realpath_cache_ttl', '1200');
    ini_set('pcre.jit', '1');
    $options = parseArgs($argv);
    $str = php_strip_whitespace($options[0]);
    $str2 = file_get_contents($options[0]);
    $l_UnicodeContent = Helpers::detect_utf_encoding($str);
    $l_UnicodeContent2 = Helpers::detect_utf_encoding($str2);
    if ($l_UnicodeContent !== false) {
        if (function_exists('iconv')) {
            $str = iconv($l_UnicodeContent, "UTF-8", $str);
            $str2 = iconv($l_UnicodeContent2, "UTF-8", $str2);
        }
    }
    $d = new Deobfuscator($str, $str2);
    $start = microtime(true);
    $deobf_type = $d->getObfuscateType($str);
    if ($deobf_type != '') {
        $str = $d->deobfuscate();
    }
    $code = $str;
    if (isset($options['prettyprint'])) {
        $code = Helpers::normalize($code);
        $code = Helpers::format($code);
    }
    if ($l_UnicodeContent !== false) {
        if (function_exists('iconv')) {
            $code = iconv('UTF-8', $l_UnicodeContent . '//IGNORE', $code);
        }
    }
    echo $code;
    echo "\n";
    //echo 'Execution time: ' . round(microtime(true) - $start, 4) . ' sec.';
}

class Deobfuscator
{
    const PCRE_BACKTRACKLIMIT = 4000000;
    const PCRE_RECURSIONLIMIT = 40000;

    private static $signatures = [
        [
            'full' => '~(\$\w+)=(\'[^\']+\');\s*eval\(gzinflate\(str_rot13\((\$_D)\(\1\)+;~msi',
            'id' => 'undefinedDFunc',
        ],
        [
            'full' => '~(\$[\w_]{1,50})\s*=\s*\[\s*base64_decode\s*\(\s*[\'"]([\w=]+)[\'"]\s*\)\s*,\s*([^;]{2,200})\]\s*;\s*(if\s*[^}]+}\s*else\s*{[^}]+}\s*function\s\w+[^}]+})~msi',
            'id' => 'base64Array',
        ],
        [
            'full' => '~for\((\$\w{1,40})=\d+,(\$\w+)=\'([^\$]+)\',(\$\w+)=\'\';@?ord\(\2\[\1\]\);\1\+\+\)\{if\(\1<\d+\)\{(\$\w+)\[\2\[\1\]\]=\1;\}else\{\$\w+\.\=@?chr\(\(\5\[\2\[\1\]\]<<\d+\)\+\(\5\[\2\[\+\+\1\]\]\)\);\}\}\s*.{0,500}eval\(\4\);(if\(isset\(\$_(GET|REQUEST|POST|COOKIE)\[[\'"][^\'"]+[\'"]\]\)\)\{[^}]+;\})?~msi',
            'fast' => '~for\((\$\w{1,40})=\d+,(\$\w+)=\'([^\$]+)\',(\$\w+)=\'\';@?ord\(\2\[\1\]\);\1\+\+\)\{if\(\1<\d+\)\{(\$\w+)\[\2\[\1\]\]=\1;\}else\{\$\w+\.\=@?chr\(\(\5\[\2\[\1\]\]<<\d+\)\+\(\5\[\2\[\+\+\1\]\]\)\);\}\}\s*.{0,500}eval\(\4\);~msi',
            'id'   => 'parenthesesString',
        ],
        [
            'full' => '~\$codelock_rfiled=dirname\(__FILE__\);(?:\s*\$codelock_fixpath=\'\';)?\s*if\s*\(\$codelock_file\s*==\s*\'\'\)\s*\{\s*echo\s*"[^"]+";\s*die\(\);\s*\}\s*else\s*\{\}\s*\$codelock_lock="([^"]+)";\s*eval\((gzinflate\()?base64_decode\(\$codelock_lock\)\)\)?;\s*return;\s*\?>\s*([\w\+\/=\$\)\(]+)~msi',
            'id' => 'codeLockDecoder',
        ],
        [
            'full' => '~error_reporting\(0\);\s*set_time_limit\(0\);\s*session_start\(\);\s*\$\w+\s*=\s*"[^"]+";(\s*function\s*(\w+)\((\$\w+)\)\{\s*@?((?:\w+\()+)\3(\)+);\s*}\s*(\$\w+)="([^"]+)";\s*\2\(\6\);)~msi',
            'id' => 'agustus1945',
        ],
        [
            'full' => '~@?eval\(str_rot13\(\s*(["\'])(riny\(pbaireg_hhqrpbqr\((?:[^;]+;)+)\1\s*\)\);~msi',
            'id' => 'strRot13ConvertUUDecode',
        ],
        [
            'full' => '~(\$\w+)="([^"]+)";\s*(\$\w+)=@?\1\(\'([^\']+)\',"([^"]+)"\);\s*@?\3\("([^"]+)"\);~msi',
            'id' => 'createFuncHex',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"([^"]+)";\s*function\s*(\w+)\(\$\w+\)\s*\{\s*\$\w+\s*=\s*strrev\("\(lave"\);\s*(\$\w+)\s*=\s*\$\w+\s*\.\s*"base64_decode\("\s*\.\s*base64_decode\(strrev\(\$\w+\)\)\s*\.\s*"\)\);";\s*eval\(strrev\(strrev\(\4\)\)\);\s*}\s*\$\w+\s*=\s*strrev\("\("\);\s*\$\w+\s*=\s*strrev\(""\{\$\w+\}""\);\s*\$\w+\s*=\s*strrev\("\)"\);\s*\$\w+\s*=\s*strrev\("\)"\);\s*(\$\w+)\s*=(?:\s*\$\w+\s*\.?)+;\s*\3\(strrev\(base64_encode\(\5\)\)\);~msi',
            'id' => 'evalStrrev',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"([^"]+)";\s*eval\(base64_decode\(substr\(strrev\(\1\),\s*(\d+),(\-\d+)\)\)\);~msi',
            'id' => 'evalSubstr',
        ],
        [
            'full' => '~((?:\$\w+\.?=\'[^\']+\';\s*)+)\$\w+=\$\w+;function\s*(\w+)\((\$\w+),(\$\w+)\)\s*\{(\$\w+)=\'\';for\((\$\w+)=0;\6<strlen\(\3\);\)for\(\5=0;\5<strlen\(\4\);\5\+\+,\6\+\+\)(\$\w+)\.=\3\{\6\}\^\4\{\5\};return\s*\7;\};(\$\w+)=base64_decode\(\8\);@?(\$\w+)=\2\(\8,\'([^\']+)\'\);@?eval\(@?gzuncompress\(\9\)\);~msi',
            'id' => 'XorGzUncompress',
        ],
        [
            'full' => '~(\$\w+)="([^"]+)";\s*(\$\w+)\s*=\s*str_replace\("([^"]+)","","([^"]+)"\);\s*(\$\w+)=\'([base64_dco\.\']+)\';\s*@?eval\(\6\(\3\("([^"]+)",\s*"",\s*\1\)\)\);~msi',
            'id' => 'evalStrReplace',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"([^"]+)";(\$\w+)\s*=\s*base64_decode\("([^"]+)"\);eval\(base64_decode\(\3\)\);(?:\s*\$\w+\s*=\s*"[^"]+";)?~msi',
            'id'   => 'sistemitComEnc',
        ],
        [
            'full' => '~(function\s*(\w+)\((\$\w+)\){\s*return\s*(base64_decode|gzinflate|eval)\(\$\w+(,\d+)?\);}\s*)+(\$\w+)="([^"]+)";(preg_replace\(\'/\.\*/e\',"([\\\\x0-9a-f]+)",\'\.\'\);)~msi',
            'id'   => 'funcs',
        ],
        [
            'full' => '~if\(!defined\(\'(\w+)\'\)\)define\(\'\1\',__FILE__\);(?:\s*@eval\(base64_decode\(\'([^\']+)\'\)\);)+\s*@chop\(base64_decode\(\'([^\']+)\'\)~msi',
            'id'   => 'fakeChop',
        ],
        [
            'full' => '~(?:\$\w+\s*=\s*"[^"]*"(?:\.\$\w+)?;\s*)+(\$\w+)=(?:\$\w+\.?)+;\s*eval\(str_rot13\(gzinflate\(str_rot13\(base64_decode\(\(\1\)\)\)\)\)\);~msi',
            'id' => 'R4C',
        ],
        [
            'full' => '~((?:\$GLOBALS\["[^"]+"\]=base64_decode\("[^"]*"\);)+).{0,10}((?:\$GLOBALS\[\$GLOBALS\["[^"]+"\]\]=base64_decode\(\$GLOBALS\["[^"]+"\]\);)+).{0,10}(?:((?:\$GLOBALS\[\$GLOBALS\[\$GLOBALS\["[^"]+"\]\]\]=base64_decode\(\$GLOBALS\[\$GLOBALS\["[^"]+"\]\]\);)+).{0,10}(\$\w+)=\$_POST\[\$GLOBALS\[\$GLOBALS\[\$GLOBALS\["[^"]+"\]\]\]\];if\(\4\!=\$GLOBALS\[\$GLOBALS\[\$GLOBALS\["[^"]+"\]\]\]\)\s*\{(\$\w+)=base64_decode\(\$_POST\[\$GLOBALS\[\$GLOBALS\[\$GLOBALS\["[^"]+"\]\]\]\]\);)?@?eval\((?:"\\\\\$\w+=\5;"\);\}|(?:\w+\()+\$GLOBALS\[\$GLOBALS\["([^"]+)"\]\]\)\)\)\);)~msi',
            'id' => 'manyGlobals',
        ],
        [
            'full' => '~eval\(\'\$(\w+)\s*=\s*"([^"]+)";\$(\w+)\s*=\s*"([^"]+)";(eval\((?:\w+\()+)(\$\{"\3"\}\s*\.\s*\$\{"\1"})(\)+;)\'\);~msi',
            'id' => 'blackshadow',
        ],
        [
            'full' => '~(?:\$[^;\s]+\s*=\s*\d;\s*[^;\s]+:\s*if\s*\([^\)]+\)+\s*\{\s*goto\s*[^;\s]+;\s*\}\s*\$[^;\s]+[^:]+:\s*[^;]+;\s*)?goto [^;\s]+;\s*([^;\s]+:\s*([^;\s]+:\s*)?.*?goto\s*[^;\s]+;\s*(}\s*goto\s*[^;\s]+;)?(goto\s*[^;\s]+;)?\s*)+[^;\s]+:\s*[^;>]+;(\s*goto\s*[^;\s]+;\s*[^;\s]+:\s*[^;\s]+:\s*|(?:\s*die;\s*}\s*)?\s*goto\s*[^;\s]+;\s*[^;\s]+:\s*\}?)?(?:(?:.*?goto\s*\w{1,50};)?(?:\s*\w{1,50}:\s?)+)?(?:(?:[^;]+;\s*goto\s*\w+;\s*)+\w+:\s*include\s*[^;]+;)?~msi',
            'fast' => '~goto [^;\s]+;\s*([^;\s]+:\s*([^;\s]+:\s*)?.*?goto\s*[^;\s]+;\s*(}\s*goto\s*[^;\s]+;)?(goto\s*[^;\s]+;)?\s*)+[^;\s]+:\s*[^;]+(?:;|\?>)~msi',
            'id' => 'goto',
        ],
        [
            'full' => '~\$\w+\s=\sfile_get_contents\(base64_decode\(["\'][^"\']+["\']\)\s\.\sbase64_decode\(["\'][^"\']+[\'"]\)\s\.\s\$\w+\s\.\s["\'][^\'"]+["\']\s\.\s\$_SERVER\[["\'][^\'"]+[\'"]\]\s\.\s["\'][^"\']+["\']\s\.\s\$_SERVER\[["\'][^"\']+["\']\]\);.*?\s\$\w+\s=\sbase64_decode\(["\'][^"\']+["\']\);\s.*?\s@unlink\(\$_SERVER\[["\'][^"\']+["\']\]\);~msi',
            'id' => 'gotoBase64Decode',
        ],
        [
            'full' => '~(?:\$\w{1,50}\s?=\s?(?:str_rot13\(\$\w{1,50}\)|[\'"][^"\']+[\'"]|base64_decode\("(?:{\$\w{1,50}})+"\));\s*)+(\$\w{1,50})\s?=\s?base64_decode\("((?:{\$\w{1,50}})+)"\);\s?eval\(\1\);~msi',
            'id' => 'gotoStrRot13Vars',
        ],
        [
            'full' => '~(\$\{"GLOBALS"\}\["\w+"\])\s*=\s*"\w+";\s*(?:\$\{"GLOBALS"\}\["(\w+)"\]\s*=\s*"\w+";\s*)+.*?;\s*\$\{\1\}\s*=\s*[\"\'][^;]+[\"\'];\s*exec\(\$\w+\);\s*echo\s*"[^"]+";\s*\}\s*\}~msi',
            'id' => 'gotoShell',
        ],
        [
            'full' => '~(?:\$\w+\s*=\s*\'[^\']++\';\s*)*eval\(base64_decode\(substr\("(?:[^"]++)",(?:\d+),(?:-?\d+)\)\.base64_decode\(strrev\("[^"]++"(?:\.(?:substr\("(?:[^"]++)",(?:\d++),(?:-?\d++)\)|"(?:[^"]+)"))++\)\)\)\);(?:\$\w+\s*=\s*\'[^\']++\';\s*)*~msi',
            'id'   => 'substrEmpty',
        ],
        [
            'full' => '~function\s{0,50}(\w+)\((\$\w+)\)\s{0,50}\{\s{0,50}\2\s{0,50}=\s{0,50}substr\(\2,\s{0,50}\(int\)\s{0,50}\(?hex2bin\(([\'"])([0-9a-f]+)\3\)\)\)?;\s{0,50}\2\s{0,50}=\s{0,50}substr\(\2,\s{0,50}\(int\)\s{0,50}\(?hex2bin\(([\'"])([0-9a-f]+)\5\)\)?,\s{0,50}\(int\)\s{0,50}\(?hex2bin\(([\'"])([0-9a-f]+)\7\)\)\)?;\s{0,50}return\s{0,50}\2;\s{0,50}\}\s{0,50}(\$\w+)\s{0,50}=\s{0,50}([\'"])[^\'"]+\10;\s{0,50}(\$\w+)\s{0,50}=\s{0,50}[\'"]base64_decode[\'"];\s{0,50}function\s{0,50}\w+\((\$\w+)\)\s{0,50}{\s{0,50}global\s{0,50}\9;\s{0,50}global\s{0,50}\11;\s{0,50}return\s{0,50}strrev\(gzinflate\(\11\(\1\(\12\)\)\)\);\s{0,50}\}\s{0,50}(?:(?:eval\()+\w+\(([\'"]))?([^\'"]+)\13\)+;~msi',
            'id'   => 'Obf_20200522_1',
        ],
        [
            'full' => '~(\$auth_pass\s*=\s*"[^"]+";\s*(?:/\*[^\*]+\*/\s*)?)\$__="";((?:\$__=\$__\."[^"]+";\s*)+)\$\w+=\$__;function\s*(\w+)\((\$\w+),\s*(\$\w+)\)\{\s*for\((\$\w+)=0;\6<strlen\(\4\);\)\s*for\((\$\w+)=0;\7<strlen\(\5\);\7\+\+,\s*\6\+\+\)\s*(\$\w+)\s*\.=\s*\4\{\6\}\s*\^\s*\5\{\7\};\s*return\s*\8;\s*\};(\$\w+)=base64_decode\(\9\);\$__=\3\(\9,"([^"]+)"\);\$_=create_function\("",\$__\);\$_\(\);~msi',
            'id' => 'b64xoredkey',
        ],
        [
            'full' => '~(eval\(gzinflate\(base64_decode\("([^"]+)"\)\)\);\s*)((?:eval\((?:\$\w+\()+"[^"]+"\)+;\s*)+)~msi',
            'id' => 'linesCond',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*\'[\'.error_reporting]+;\s*\1\(0\);((?:\s*\$\w+\s*=\s*[\'abcdefgilnorstz64_.]+;)+)((?:\s*\$\w+\s*=\s*\'[^;]+\';)+)((?:\s*\$\w+\()+)(\$\w+)[\s\)]+;\s*die\(\);~mis',
            'id'   => 'blackScorpShell',
        ],
        [
            'full' => '~(?(DEFINE)(?\'c\'(?:/\*\w+\*/)*))(\$\w+)\s*=\s*basename(?&c)\((?&c)trim(?&c)\((?&c)preg_replace(?&c)\((?&c)rawurldecode(?&c)\((?&c)"[%0-9A-F\.]+"(?&c)\)(?&c),\s*\'\',\s*__FILE__(?&c)\)(?&c)\)(?&c)\)(?&c);(\$\w+)\s*=\s*"([%\w\.\-\~]+)";(?:(\$\w+)=[^;]+;\5(?&c)\((?&c)\'\',\s*\'};\'\s*\.\s*(?&c)\()?(?:eval(?&c)\()?(?&c)rawurldecode(?&c)\((?&c)\3(?&c)\)(?&c)\s*\^\s*substr(?&c)\((?&c)str_repeat(?&c)\((?&c)\2,\s*(?&c)\((?&c)strlen(?&c)\((?&c)\3(?&c)\)(?&c)/strlen(?&c)\((?&c)\2(?&c)\)(?&c)\)(?&c)\s*\+\s*1(?&c)\)(?&c),\s*0,(?&c)\s*strlen(?&c)\((?&c)\3(?&c)\)(?&c)\)(?&c)\)(?:(?&c)\s*\.\s*\'{\'(?&c)\))?(?&c);~msi',
            'id'   => 'xorFName',
        ],
        [
            'full' => '~(\$\w{1,40})=base64_decode\(\'[^\']+\'\);(\$\w+)=base64_decode\(\'[^\']+\'\);(\$\w+)=base64_decode\(\'([^\']+)\'\);eval\(\1\(gzuncompress\(\2\(\3\)\)\)\);~msi',
            'id'   => 'phpMess',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*\"([^\"]+)\";\s*\$\w+\s*=\s*\$\w+\(\1,\"[^\"]+\",\"[^\"]+\"\);\s*\$\w+\(\"[^\"]+\",\"[^\"]+\",\"\.\"\);~msi',
            'id'   => 'pregReplaceSample05',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*\w+\(\'.+?\'\);\s*(\$\w+)\s*=\s*\w+\(\'.+?\'\);\s*(\$\w+)\s*=\s*\"([^\"]+)\";\s*(\$\w+)\s*=\s*.+?;\s*\2\(\5,\"[^\']+\'\3\'[^\"]+\",\"\.\"\);~msi',
            'id'   => 'pregReplaceB64',
        ],
        [
            'full' => '~preg_replace\([\'"]/\(\.\*\)/e[\'"],[\'"]([^\'"]+)[\'"],\s?NULL\);~msi',
            'id'   => 'pregReplaceStr',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*\'([^\']+)\';\s*\1\s*=\s*gzinflate\s*\(base64_decode\s*\(\1\)\);\s*\1\s*=\s*str_replace\s*\(\"__FILE__\",\"\'\$\w+\'\",\1\);\s*eval\s*\(\1\);~msi',
            'id'   => 'GBE',
        ],
        [
            'full' => '~(\$GLOBALS\[\s*[\'"]_+\w{1,60}[\'"]\s*\])\s*=\s*\s*array\s*\(\s*base64_decode\s*\(.+?((.+?\1\[\d+\]).+?)+[^;]+;(\s*include\(\$_\d+\);)?}?((.+?_+\d+\(\d+\))+[^;]+;)?(.*?(\$[a-z]+).+\8_\d+;)?(echo\s*\$\w+;})?}?(?:unset.*?[^}]+})?~msi',
            'fast' => '~\$GLOBALS\[\s*[\'"]_+\w{1,60}[\'"]\s*\]\s*=\s*\s*array\s*\(\s*base64_decode\s*\(~msi',
            'id'   => 'Bitrix',
        ],
        [
            'full' => '~\$\w{1,40}\s*=\s*(__FILE__|__LINE__);\s*\$\w{1,40}\s*=\s*(\d+);\s*eval(\s*\()+\$?\w+\s*\([\'"][^\'"]+[\'"](\s*\))+;\s*return\s*;\s*\?>(.+)~msi',
            'id'   => 'B64inHTML',
        ],
        [
            'full' => '~<\?php\s+(?:/[*/].*?)?(?:\$[O0]*=__FILE__;\s*)?(\$[O0]*)=urldecode\(\'([%a-f0-9]+)\'\);(\$(GLOBALS\[\')?[O0]*(\'\])?=(\d+);)?(.*?)(\$(GLOBALS\[\')?[O0]*(\'\])?\.?=(\$(GLOBALS\[\')?[O0]*(\'\])?([{\[]\d+[}\]])?\.?)+;)+([^\?]+)\?\>[\s\w\~=/+\\\\^{`%|@[}]+~msi',
            'fast' => '~(\$[O0]*)=urldecode\(\'([%a-f0-9]+)\'\);(\$(GLOBALS\[\')?[O0]*(\'\])?=(\d+);)?(.*?)(\$(GLOBALS\[\')?[O0]*(\'\])?\.?=(\$(GLOBALS\[\')?[O0]*(\'\])?([{\[]\d+[}\]])?\.?)+;)+([^\?]+)\?\>[\s\w\~=/+\\\\^{`%|@[}]+~msi',
            'id'   => 'LockIt',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*\"(\\\\142|\\\\x62)[0-9a-fx\\\\]+";\s*@?eval\s*\(\1\s*\([^\)]+\)+\s*;~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*\"(\\\\142|\\\\x62)[0-9a-fx\\\\]+";\s*@?eval\s*\(\1\s*\(~msi',
            'id'   => 'FOPO',
        ],
        [
            'full' => '~\$_F=__FILE__;\$_X=\'([^\']+\');eval\([^\)]+\)+;~msi',
            'fast' => '~\$_F=__FILE__;\$_X=\'([^\']+\');eval\(~ms',
            'id'   => 'ByteRun',
        ],
        [
            'full' => '~(\$\w{1,40}=\'[^\']+\';\s*)+(\$[\w{1,40}]+)=(urldecode|base64_decode){0,1}\(?[\'"]([\w+%=-]+)[\'"]\)?;((\$\w+)=[^;]+;)+[^\(]+\(\'Content-Type.*?;\${"[^"]+"}\["[\\\\x0-9a-f]+"\]\(\);~msi',
            'id'   => 'Urldecode',
        ],
        [
            'full' => '~(\$[\w{1,40}]+)\s?=\s?(urldecode|base64_decode)\(?[\'"]([\w+%=\-/\\\\\*]+)[\'"]\);(\s*\$\w+\.?\s?=\s?((?:\$\w+\s*\.\s*)?\$\w+[{\[]\d+[}\]]\s*[\.;]?\s*)+)+((\$\w+=["\']([^\'"]+)[\'"];\s*eval\(\'\?>\'\.[\$\w\(\)\*\d,\s]+);|(eval\(\s*\$\w+\([\'"]([^\'"]+)[\'"][)\s]+;)|header\(\'[^\']+\'\);(?:\$\w+=\${[^}]+}\[[^\]]+\]\(\'.*?\'?;}?\'\);)+\${[^}]+}\[[^\]]+\]\(\);)~msi',
            'id'   => 'UrlDecode2',
        ],
        [
            'full' => '~(?:\$\w{1,40}\s?=\s?[\'"]?[\d\w]+[\'"]?;\s*)*()(?|(?:(\$\w{1,40})=[\'"]([^\'"]+)[\'"];\s*)+(?:global\s*\$\w+;\s*)?(\$[\w{1,40}]+)=urldecode\(\2\);|(\$\w{1,40})=urldecode\([\'"]([^\'"]+)[\'"]\);function\s*\w+\([^{]+\{global\s*(\$\w+);)\s*.+?\4(?:.{1,1000}\4[{\[]\d+[}\]]\.?)+?.*?(?:function\s*(\w+)\(\$\w+\s*=\s*\'\'\)\{global\s*\4;@.+\5\(\);|function\s*\w+\(\$\w+,\s*\$\w+,\s*\$\w+\)\s*\{\$\w+\s*[^)]+\)[^}]+;\}|header\((?:\4[\[\{]\d+[\]\}]\.?)+\);})~msi',
            'id'   => 'UrlDecode3',
        ],
        [
            'full' => '~(?:@?session_start\(\);)?(?:@?(?:set_time_limit|error_reporting)\(\d+\);){1,2}(?:ini_set\(base64_decode\([\'"][^\'"]+[\'"]\)|@\$\w{1,50}=\$_POST\[base64_decode\([\'"][^\'"]+[\'"]\)\];|if\((?:\w{1,50}\(\)\){foreach\(\$_POST\s{0,50}as\s{0,50}\$\w{1,50}=>\$\w{1,50}\)|\$_GET|!empty\(\$_SERVER\[))(?:.*?base64_decode\([\'"][^\'"]+[\'"]\)+\.?){1,200}\]?(?:\)\)|;})?(?:;return\s?\$\w{1,50};})?;?~msi',
            'id' => 'manyBase64DecodeContent',
        ],
        [
            'full' => '~echo\s{0,50}base64_decode\(\'[^\']+\'\);\s{0,50}echo\s{0,50}base64_decode\(\'[^\']+\'\)\.php_uname\(\)\.base64_decode\(\'[^\']+\'\);.*?else\s{0,50}{\s{0,50}echo\s{0,50}base64_decode\(\'[^\']+\'\);\s{0,50}}}}~msi',
            'id' => 'manyBase64DecodeContent',
        ],
        [
            'full' => '~{(\$\w{1,100})\s?=(?:\s?base64_decode\(\'[^\']+\'\)\.?)+;(\$\w{1,100})\s?=\s?\1\(base64_decode\(\'[^\']+\'\),(?:\s?base64_decode\(\'[^\']+\'\)\.?)+\);\2\(base64_decode\(\'([^\']+)\'\)\);exit;}~msi',
            'id' => 'manyBase64DecodeContent',
        ],
        [
            'full' => '~eval\(base64_decode\(\'[^\']+\'\)\.file_get_contents\(base64_decode\(\'[^\']+\'\)\)\);~msi',
            'id' => 'manyBase64DecodeContent',
        ],
        [
            'full' => '~\$\w{1,50}\s?=\s?\$\w{1,50}->get\(base64_decode\([\'"][^\'"]+[\'"]\)(?:.*?base64_decode\([\'"][^\'"]+[\'"]\)){1,200}\)\s?\)\s?{~msi',
            'id' => 'manyBase64DecodeContent',
        ],
        [
            'full' => '~explode\(\"\*\*\*\",\s*\$\w+\);\s*eval\(eval\(\"return strrev\(base64_decode\([^\)]+\)+;~msi',
            'fast' => '~explode\(\"\*\*\*\",\s*\$\w+\);\s*eval\(eval\(\"return strrev\(base64_decode\(~msi',
            'id'   => 'cobra',
        ],
        [
            'full' => '~\$[O0]+=\(base64_decode\(strtr\(fread\(\$[O0]+,(\d+)\),\'([^\']+)\',\'([^\']+)\'\)\)\);eval\([^\)]+\)+;~msi',
            'fast' => '~\$[O0]+=\(base64_decode\(strtr\(fread\(\$[O0]+,(\d+)\),\'([^\']+)\',\'([^\']+)\'\)\)\);eval\(~msi',
            'id'   => 'strtrFread',
        ],
        [
            'full' => '~if\s*\(\!extension_loaded\(\'IonCube_loader\'\)\).+pack\(\"H\*\",\s*\$__ln\(\"/\[A-Z,\\\\r,\\\\n\]/\",\s*\"\",\s*substr\(\$__lp,\s*([0-9a-fx]+\-[0-9a-fx]+)\)\)\)[^\?]+\?\>\s*[0-9a-z\r\n]+~msi',
            'fast' => '~IonCube_loader~ms',
            'id'   => 'FakeIonCube',
        ],
        [
            'full' => '~(\$\w{1,40})="([\w\]\[\<\&\*\_+=/]{300,})";\$\w+=\$\w+\(\1,"([\w\]\[\<\&\*\_+=/]+)","([\w\]\[\<\&\*\_+=/]+)"\);~msi',
            'id'   => 'strtrBase64',
        ],
        [
            'full' => '~\$\w+\s*=\s*array\((\'[^\']+\',?)+\);\s*.+?(\$_\w{1,40}\[\w+\])\s*=\s*explode\(\'([^\']+)\',\s*\'([^\']+)\'\);.+?(\2\[[a-fx\d]+\])\(\);(.+?\2)+.+}~msi',
            'fast' => '~(\$_\w{1,40}\[\w+\])\s*=\s*explode\(\'([^\']+)\',\s*\'([^\']+)\'\);.+?(\1\[[a-fx\d]+\])\(\);~msi',
            'id'   => 'explodeSubst',
        ],
        [
            'full' => '~(\$[\w{1,40}]+)\s*=\s*\'([\w+%=\-\#\\\\\'\*]+)\';(\$[\w+]+)\s*=\s*Array\(\);(\3\[\]\s*=\s*(\1\[\d+\]\.?)+;+)+(.+\3)[^}]+}~msi',
            'fast' => '~(\$[\w{1,40}]+)\s*=\s*\'([\w+%=\-\#\\\\\'\*]+)\';(\$[\w+]+)\s*=\s*Array\(\);(\3\[\]\s*=\s*(\1\[\d+\]\.?)+;+)+~msi',
            'id'   => 'subst',
        ],
        [
            'full' => '~if\s{0,50}\(!(?:function_exists|\$\W{1,50})\(\"([\w\W]{1,50})\"\)\)\s{0,50}{\s{0,50}function \1\(.+?eval\(\1\(\"([^\"]+)\"\)\);~msi',
            'fast' => '~if\s{0,50}\(!(?:function_exists|\$\W{1,50})\(\"([\w\W]{1,50})\"\)\)\s{0,50}{\s{0,50}function \1\(.+?eval\(\1\(\"[^\"]+\"\)\);~msi',
            'id'   => 'decoder',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*\"riny\(\"\.(\$\w+)\(\"base64_decode\"\);\s*(\$\w+)\s*=\s*\2\(\1\.\'\("([^"]+)"\)\);\'\);\s*\$\w+\(\3\);~msi',
            'id'   => 'GBZ',
        ],
        [
            'full' => '~\$\w+\s*=\s*\d+;\s*\$GLOBALS\[\'[^\']+\'\]\s*=\s*Array\(\);\s*global\s*\$\w+;(\$\w{1,40})\s*=\s*\$GLOBALS;\$\{"\\\\x[a-z0-9\\\\]+"\}\[(\'\w+\')\]\s*=\s*\"(([^\"\\\\]|\\\\.)*)\";\1\[(\1\[\2\]\[\d+\].?).+?exit\(\);\}+~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*\$GLOBALS;\$\{"\\\\x[a-z0-9\\\\]+"\}\[(\'\w+\')\]\s*=\s*\"(([^\"\\\\]|\\\\.)*)\";\1\[(\1\[\2\]\[\d+\].?)~msi',
            'id'   => 'globalsArray',
        ],
        [
            'full' => '~(\${(["\w\\\\]+)}\[["\w\\\\]+\]=["\w\\\\]+;)+((\${\${(["\w\\\\]+)}\[["\w\\\\]+\]}).?=((urldecode\(["%\w]+\);)|(\${\${["\w\\\\]+}\[["\w\\\\]+\]}{\d+}.?)+;))+eval\(\${\${["\w\\\\]+}\[["\w\\\\]+\]}\(["\w+=]+\)\);~msi',
            'id'   => 'xbrangwolf',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*\'(\\\\.|[^\']){0,100}\';\s*\$\w+\s*=\s*\'(\\\\.|[^\']){0,100}\'\^\1;[^)]+\)+;\s*\$\w+\(\);~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*\'(\\\\.|[^\']){0,100}\';\s*\$\w+\s*=\s*\'(\\\\.|[^\']){0,100}\'\^\1;~msi',
            'id'   => 'xoredVar',
        ],
        [
            'full' => '~(?:(?:\$\w+=\'[^\']+\';\s*)+(?:\$\w+=\'[^\']+\'\^\'[^\']+\';\s*)+.{0,50})?\$\w{1,40}=\'[^\']{0,100}(?:\'\^\')?[^\']*\';(?:\$\w{1,40}=\w{1,3};)?(?:\$\w{1,40}=\'[^\']+(?:\'\^\')?[^\']*\';)+(?:.{0,6000}?)if\(\$\w{1,40}==\$\w{1,40}\(\$\w{1,40}\)\){(?:.{0,6000}?)(\$\w+)=\$\w+\(\$\w+,\$\w+\);\1\(\'[^\']+\',\'[^\']+\'\);}.{0,300}\$\w{1,40}(?:\(\'[^\']{0,100}\',\'[^\']{0,100}\'\))?(?:.{0,300}\s*;\s*\'[^\']+\';){0,2}~msi',
            'fast' => '~\$\w{1,40}=\'[^\']{0,100}(?:\'\^\')[^\']*\';(?:\$\w{1,40}=\'[^\']+(?:\'\^\')?[^\']*\';)+~msi',
            'id'   => 'xoredVar',
        ],
        [
            'full' => '~(\$\w+)=fopen\(__FILE__,\'r\'\);(\$\w+)=fread\(\1,filesize\(__FILE__\)\);fclose\(\1\);(\$\w+)=explode\(hex2bin\(\'([^\']+)\'\),\2\)\[(\d)\];(\$\w+)=\[\];for\((\$\w+)=0;\7<strlen\(\3\);\7\+\+\)\6\[\]=ord\(\3\[\7\]\)\s*xor\s*\7;eval\(hex2bin\(base64_decode\(implode\(array_map\(hex2bin\(\'([^\']+)\'\),\6\)\)\)\)\);__halt_compiler\(\);\w+~msi',
            'id' => 'D5',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*\'([^\']*)\';\s*(\$\w{1,40})\s*=\s*explode\s*\((chr\s*\(\s*\(\d+\-\d+\)\)),substr\s*\(\1,\s*\((\d+\-\d+)\),\s*\(\s*(\d+\-\d+)\)\)\);\s*(\$\w{1,40})\s*=\s*\3\[\d+\]\s*\(\3\[\s*\(\d+\-\d+\)\]\);\s*(\$\w{1,40})\s*=\s*\3\[\d+\]\s*\(\3\[\s*\(\d+\-\d+\)\]\);\s*if\s*\(!function_exists\s*\(\'([^\']*)\'\)\)\s*\{\s*function\s*\9\s*\(.+\1\s*=\s*\$\w+[+\-\*]\d+;~msi',
            'fast' => '~(\$\w{1,40})\s=\s\'([^\']*)\';\s(\$\w{1,40})=explode\((chr\(\(\d+\-\d+\)\)),substr\(\1,\((\d+\-\d+)\),\((\d+\-\d+)\)\)\);\s(\$\w{1,40})\s=\s\3\[\d+\]\(\3\[\(\d+\-\d+\)\]\);\s(\$\w{1,40})\s=\s\3\[\d+\]\(\3\[\(\d+\-\d+\)\]\);\sif\s\(!function_exists\(\'([^\']*)\'\)\)\s\{\sfunction\s*\9\(~msi',
            'id'   => 'arrayOffsets',
        ],
        [
            'full' => '~(\$\w+)\s?=\s?[\'"](.*?)[\'"];\s?(\$\w+)\s?=\s?explode\(chr\(+(\d+\s?[-+]\s?\d+)\)+,\s?[\'"]((?:\d+,?)+)[\'"]\);\s?(\$\w+)\s?=\s?substr\(\1,\s?\(+(\d+\s?[-+]\s?\d+)\),\s?\(+(\d+\s?[-+]\s?\d+)\)\);\s?if\s?\(!function_exists\([\'"](\w+)[\'"]\)\)\s?{\s?function\s?\9\((\$\w+),\s?(\$\w+)\)\s?{\s?(\$\w+)\s?=\s?NULL;\s?for\s?\((\$\w+)\s?=\s0;\s?\13\s?<\s?\(sizeof\(\10\)\s?/\s?(\d+)\);\s?\13\+\+\)\s?{\s?\12\s?\.=\s?substr\(\11,\s?\10\[\(\13\s?\*\s?(\d+)\)\],\s?\10\[\(\13\s?\*\s?(\d+)\)\s?\+\s?(\d+)\]\);\s?}\s?return\s?\12;\s?}\s;\s?}\s?(\$\w+)\s?=\s?[\'"](.*?eval\(str_replace\(chr\(\(+(\d+\s?[-+]\s?\d+)\)\),\s?chr\(\(+(\d+\s?[-+]\s?\d+)\)\),\s?\9\(\3,\1\)\)\);.*?)[\'"];\s?(\$\w+)\s?=\s?substr\(\1,\s?\(+(\d+\s?[-+]\s?\d+)\),\s?\(+(\d+\s?[-+]\s?\d+)\)\);\s?\22\(\6,\s?\18,\s?NULL\);\s?\22\s?=\s?\18;\s?\22\s?=\s?\(+(\d+\s?[-+]\s?\d+)\);\s?\$\w+\s?=\s?\$\w+\s?\-\s?\d+;~msi',
            'fast' => '~(\$\w+)\s?=\s?[\'"](.*?)[\'"];\s?(\$\w+)\s?=\s?explode\(chr\(+(\d+\s?[-+]\s?\d+)\)+,\s?[\'"]((?:\d+,?)+)[\'"]\);\s?(\$\w+)\s?=\s?substr\(\1,\s?\(+(\d+\s?[-+]\s?\d+)\),\s?\(+(\d+\s?[-+]\s?\d+)\)\);\s?if\s?\(!function_exists\([\'"](\w+)[\'"]\)\)\s?{\s?function\s?\9\((\$\w+),\s?(\$\w+)\)\s?{\s?(\$\w+)\s?=\s?NULL;\s?for\s?\((\$\w+)\s?=\s0;\s?\13\s?<\s?\(sizeof\(\10\)\s?/\s?(\d+)\);\s?\13\+\+\)\s?{\s?\12\s?\.=\s?substr\(\11,\s?\10\[\(\13\s?\*\s?(\d+)\)\],\s?\10\[\(\13\s?\*\s?(\d+)\)\s?\+\s?(\d+)\]\);\s?}\s?return\s?\12;\s?}\s;\s?}\s?(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];\s?(\$\w+)\s?=\s?substr\(\1,\s?\(+(\d+\s?[-+]\s?\d+)\),\s?\(+(\d+\s?[-+]\s?\d+)\)\);\s?\20\(\6,\s?\18,\s?NULL\);\s?\20\s?=\s?\18;\s?\20\s?=\s?\(+(\d+\s?[-+]\s?\d+)\);\s?\$\w+\s?=\s?\$\w+\s?\-\s?\d+;~msi',
            'id'   => 'arrayOffsetsEval',
        ],
        [
            'full' => '~(\$\w{1,50}\s*=\s*array\((\'\d+\',?)+\);)+\$\w{1,40}=\"([^\"]+)\";if\s*\(!function_exists\(\"\w{1,50}\"\)\)\s*\{\s*function\s*[^\}]+\}\s*return\s*\$\w+;\}[^}]+}~msi',
            'fast' => '~(\$\w{1,50}=\s*array\((\'\d+\',?)+\);)+\$\w{1,40}=\"[^\"]+\";if\s*\(!function_exists\(\"\w{1,50}\"\)\)\{\s*function ~msi',
            'id'   => 'obfB64',
        ],
        [
            'full' => '~if\(\!function_exists\(\'findsysfolder\'\)\){function findsysfolder\(\$fld\).+\$REXISTHEDOG4FBI=\'([^\']+)\';\$\w+=\'[^\']+\';\s*eval\(\w+\(\'([^\']+)\',\$REXISTHEDOG4FBI\)\);~msi',
            'fast' => '~if\(!function_exists\(\'findsysfolder\'\)\){function findsysfolder\(\$fld\)\{\$fld1=dirname\(\$fld\);\$fld=\$fld1\.\'/scopbin\';clearstatcache\(\);if\(!is_dir\(\$fld\)\)return findsysfolder\(\$fld1\);else return \$fld;\}\}require_once\(findsysfolder\(__FILE__\)\.\'/911006\.php\'\);~msi',
            'id'   => 'sourceCop',
        ],
        [
            'full' => '~function\s*(\w{1,40})\s*\(\s*(\$\w{1,40})\s*,\s*(\$\w{1,40})\s*\)\s*\{\s*(\$\w{1,40})\s*=\s*str_rot13\s*\(\s*gzinflate\s*\(\s*str_rot13\s*\(\s*base64_decode\s*\(\s*[\'"][^\'"]*[\'"]\s*\)\s*\)\s*\)\s*\)\s*;\s*(if\s*\(\s*\$\w+\s*==[\'"][^\'"]*[\'"]\s*\)\s*\{\s*(\$\w{1,40})\s*=(\$\w+[\{\[]\d+[\}\]]\.?)+;return\s*(\$\w+)\(\3\);\s*\}\s*else\s*)+\s*if\s*\(\s*\$\w+\s*==[\'"][^\'"]*[\'"]\s*\)\s*\{\s*return\s*eval\(\3\);\s*\}\s*\};\s*(\$\w{1,40})\s*=\s*[\'"][^\'"]*[\'"];(\s*\9\([\'"][^\'"]*[\'"],)+\s*[\'"][^\'"]*[\'"]\s*\)+;~msi',
            'id'   => 'webshellObf',

        ],
        [
            'full' => '~(\$\w{1,40})=\'([^\'\\\\]|.*?)\';\s*((\$\w{1,40})=(\1\[\d+].?)+;\s*)+(\$\w{1,40})=\'\';\s*(\$\w{1,40})\(\6,\$\w{1,40}\.\"([^\"]+)\"\.\$\w{1,40}\.\4\);~msi',
            'fast' => '~(\$\w{1,40})=\'([^\\\\\']|.*?)\';\s*((\$\w{1,40})=(\1\[\d+].?)+;\s*)+(\$\w{1,40})=\'\';~msi',
            'id'   => 'substCreateFunc',
        ],
        [
            'full' => '~@error_reporting\(0\);\s*@ini_set\(\'error_log\',NULL\);\s*@ini_set\(\'log_errors\',0\);\s*@ini_set\(\'display_errors\',\s*0\);\s*@(\$\w+)="[create_function"\.]+;\s*(\$\w+)=\1\("([^"]+)","[eval\."]+\(\'\?>\'\.[base64_decode"\.]+\(\3\)\);"\);\s*\2\("([^"]+)"\);exit;~msi',
            'id'   => 'Obf_20200507_2',
        ],
        [
            'full' => '~\$\w+=([create_function"\'.]+);\s?\$\w+=\$\w+\([\'"]\\\\?\$\w+[\'"],((?:[\'"][eval]{0,4}[\'"]\.?)+)\.([\'"](\([\'"]\?>[\'"]\.)\w+[\'"]\.[^)\\\\]+)\\\\?\$\w+\)+;[\'"]\);\s?\$\w+\([\'"]([\w\+=\\\\\'"%/]+)[\'"]\);~msi',
            'id'   => 'createFunc',
        ],
        [
            'full' => '~(?(DEFINE)(?\'foreach\'(?:/\*\w+\*/)?\s*foreach\(\[[\d,]+\]\s*as\s*\$\w+\)\s*\{\s*\$\w+\s*\.=\s*\$\w+\[\$\w+\];\s*\}\s*(?:/\*\w+\*/)?\s*))(\$\w+)\s*=\s*"([^"]+)";\s*\$\w+\s*=\s*"";(?P>foreach)if\(isset\(\$_REQUEST\s*(?:/\*\w+\*/)?\["\$\w+"\]\)+\{\s*\$\w+\s*=\s*\$_REQUEST\s*(?:/\*\w+\*/)?\["\$\w+"\];(?:\s*\$\w+\s*=\s*"";\s*)+(?P>foreach)+\$\w+\s*=\s*\$\w+\([create_function\'\.]+\);\s*\$\w+\s*=\s*\$\w+\("",\s*\$\w+\(\$\w+\)\);\s*\$\w+\(\);\s*(?:exit\(\);)?\s*}~msi',
            'fast' => '~(?(DEFINE)(?\'foreach\'(?:/\*\w+\*/)?\s*foreach\(\[[\d,]+\]\s*as\s*\$\w+\)\s*\{\s*\$\w+\s*\.=\s*\$\w+\[\$\w+\];\s*\}\s*(?:/\*\w+\*/)?\s*))(\$\w+)\s*=\s*"([^"]+)";\s*\$\w+\s*=\s*"";(?P>foreach)if\(isset\(\$_REQUEST\s*(?:/\*\w+\*/)?\["\$\w+"\]\)+\{\s*\$\w+\s*=\s*\$_REQUEST\s*(?:/\*\w+\*/)?\["\$\w+"\];(?:\s*\$\w+\s*=\s*"";\s*)+(?P>foreach)+\$\w+\s*=\s*\$\w+\([create_function\'\.]+\);\s*\$\w+\s*=\s*\$\w+\("",\s*\$\w+\(\$\w+\)\);\s*\$\w+\(\);~msi',
            'id'   => 'forEach',
        ],
        [
            'full' => '~\$\w+\s*=\s*base64_decode\s*\([\'"][^\'"]+[\'"]\);\s*if\s*\(!function_exists\s*\("rotencode"\)\).{0,1000}eval\s*\(\$\w+\s*\(base64_decode\s*\([\'"][^"\']+[\'"]\)+;~msi',
            'id'   => 'PHPMyLicense',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*file\(__FILE__\);\s*if\(!function_exists\(\"([^\"]*)\"\)\)\{function\s*\2\((\$\w{1,40}),(\$\w{1,40})=\d+\)\{(\$\w{1,40})=implode\(\"[^\"]*\",\3\);(\$\w{1,40})=array\((\d+),(\d+),(\d+)\);if\(\4==0\)\s*(\$\w{1,40})=substr\(\5,\6\[\d+\],\6\[\d+\]\);elseif\(\4==1\)\s*\10=substr\(\5,\6\[\d+\]\+\6\[\d+\],\6\[\d+\]\);else\s*\10=trim\(substr\(\5,\6\[\d+\]\+\6\[\d+\]\+\6\[\d+\]\)\);return\s*\(\10\);\}\}\s*eval\(base64_decode\(\2\(\1\)\)\);\s*eval\(\w{1,40}\(\2\(\1\s*,\s*2\)\s*,\s*\2\(\1\s*,\s*1\)\)\);\s*__halt_compiler\(\);\s*[\w\+\=/]+~msi',
            'fast' => '~(\$\w{1,40})\s*=\s*file\(__FILE__\);\s*if\(!function_exists\(\"([^\"]*)\"\)\)\{function\s*\2\((\$\w{1,40}),(\$\w{1,40})=\d+\)\{(\$\w{1,40})=implode\(\"[^\"]*\",\3\);(\$\w{1,40})=array\((\d+),(\d+),(\d+)\);if\(\4==0\)\s*(\$\w{1,40})=substr\(\5,\6\[\d+\],\6\[\d+\]\);elseif\(\4==1\)\s*\10=substr\(\5,\6\[\d+\]\+\6\[\d+\],\6\[\d+\]\);else\s*\10=trim\(substr\(\5,\6\[\d+\]\+\6\[\d+\]\+\6\[\d+\]\)\);return\s*\(\10\);\}\}\s*eval\(base64_decode\(\2\(\1\)\)\);\s*eval\(\w{1,40}\(\2\(\1\s*,\s*2\)\s*,\s*\2\(\1\s*,\s*1\)\)\);\s*__halt_compiler\(\);~msi',
            'id'   => 'zeura',
        ],
        [
            'full' => '~<\?php\s*(\$\w{1,40})\s*=\s*file\(__FILE__\);\s*function\s(\w{1,50})\((\$\w{1,50}),(\$\w{1,50})\){(\$\w{1,50})=array\(\d+,\d+,\d+,(\d+)\);if\(\4==\d+\){(\$\w{1,50})=substr\(\3,\5\[0\]\+\5\[1\],\5\[2\]\);}elseif\(\4==\d+\){\7=substr\(\3,\5\[0\],\5\[1\]\);}elseif\(\4==\d+\){\7=trim\(substr\(\3,\5\[0\]\+\5\[1\]\+\5\[2\]\)\);}return\7;}eval\(base64_decode\(\2\(\1\[0\],\d+\)\)\);eval\(\w{1,50}\(\2\(\1\[0\],\d+\),\2\(\1\[0\],41\),\1\)\);__halt_compiler\(\);[\w+=/]+~msi',
            'fast' => '~<\?php\s*(\$\w{1,40})\s*=\s*file\(__FILE__\);\s*function\s(\w{1,50})\((\$\w{1,50}),(\$\w{1,50})\){(\$\w{1,50})=array\(\d+,\d+,\d+,(\d+)\);if\(\4==\d+\){(\$\w{1,50})=substr\(\3,\5\[0\]\+\5\[1\],\5\[2\]\);}elseif\(\4==\d+\){\7=substr\(\3,\5\[0\],\5\[1\]\);}elseif\(\4==\d+\){\7=trim\(substr\(\3,\5\[0\]\+\5\[1\]\+\5\[2\]\)\);}return\7;}eval\(base64_decode\(\2\(\1\[0\],\d+\)\)\);eval\(\w{1,50}\(\2\(\1\[0\],\d+\),\2\(\1\[0\],41\),\1\)\);__halt_compiler\(\);~msi',
            'id'   => 'zeuraFourArgs',
        ],
        [
            'full' => '~(<\?php\s*/\* This file is protected by copyright law and provided under.*?\*/(?:\s*/\*.*?\*/\s*)+\$_[0O]+="(\w+)";.*?\$_[0O]+=__FILE__;.*?\$\w+=str_replace\("\\\\n","",\$\w+\);\$\w+=str_replace\("\\\\r","",\$\w+\);.*?function\s\w+\(\$\w+,\$\w+\){\$\w+=md5\(\$\w+\)\.md5\(\$\w+\.\$\w+\);.*?\$\w+=strlen\(\$\w+\);for\(\$\w+=0;\$\w+<strlen\(\$\w+\);\$\w+\+\+\){\$\w+\.=\s?chr\(ord\(\$\w+\[\$\w+\]\)\^ord\(\$\w+\[\$\w+%\$\w+\]\)\);}return\s\$\w+;}eval\(\w+\(\w+\("([^"]+)"\),\$\w+\)\);eval\(\w+\(\$\w+\)\);exit\(\);\?)>[^"\']+~msi',
            'id'   => 'evalFileContentBySize',
        ],
        [
            'full' => '~<\?php\s*(eval(?:\(\w+)+\((substr\(file_get_contents\(__FILE__\),\s?(\d+)\))\)+;)\s*__halt_compiler\(\);\s*[\w+/]+~msi',
            'id' => 'evalFileContentOffset',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*base64_decode\(((?:(?|[\'"][\w=]+[\'"]|chr\(\d+\))\.?)+)\);(\$\w+)\s*=\s*base64_decode\(((?:(?|[\'"][\w=]+[\'"]|chr\(\d+\))\.?)+)\);(\$\w+)\s*=\s*base64_decode\(((?:(?|[\'"][\w=]+[\'"]|chr\(\d+\))\.)[^;]+)\);(\1\((\(-(\d+)-\(-\9\)\))\);@set_time_limit\((\(-(\d+)-\(-\11\)\))\);)eval\(base64_decode\(((?:(?|[\'"]\d+[\'"]|chr\(\d+\))\.?)+)\)\.gzinflate\(str_rot13\(\3\(\5\){4};~msi',
            'fast' => '~@set_time_limit\((\(-(\d+)-\(-\2\)\))\);eval\(base64_decode\(((?:(?|[\'"]\d+[\'"]|chr\(\d+\))\.?)+)\)\.gzinflate\(str_rot13\(\$\w+\(\$\w+\){4};~msi',
            'id'   => 'evalConcatedVars',
        ],
        [
            'full' => '~(\$\{"[\\\\x47c2153fGLOBALS]+"\}\["[\w\\\\]+"\]="[\w\\\\]+";(\$\w+="\w+";)?){5,}.+\$\{"[\\\\x47c2153fGLOBALS]+"\}\["[\w\\\\]+"\].+?}+(?:exit;}+if\(@?file_exists\("[^"]+"\)+{include\("[^"]+"\);\}|==\(string\)\$\{\$\w+\}\)\s*\{\$\w+="[^"]+";\$\w+="[^"]+";\$\{\$\w+\}\.=\$\{\$\w+\};break;\}+eval\("[^"]+"\.gzinflate\(base64_decode\(\$\{\$\{"[^"]+"\}\["[^"]+"\]\}\)+;|\["[^"]+"\]\}\);)?~msi',
            'id'   => 'Obf_20200618_1',
        ],
        [
            'full' => '~(\$\w+\s?=\s?(\w+)\(\'\d+\'\);\s*)+\$\w+\s?=\s?new\s?\$\w+\(\2\(\'(\d+)\'\)+;\s?error_reporting\(0\);\s?eval\(\$\w+\(\$\w+->\$\w+\("([^"]+)"\)+;.+?function \2.+?return\s\$\w+;\s}~msi',
            'id'   => 'aanKFM',
        ],
        [
            'full' => '~error_reporting\(\d\);@?set_time_limit\(\d\);(\$\w{1,50})\s?=\s?[\'"]([^\'"]+)[\'"];(\$\w{1,50})\s?=\s?[\'"]([^\'"]+)[\'"];(\$\w{1,50})\s?=\s?[\'"]([^\'"]{0,100})[\'"];(\$\w{1,50}\s?=\s?[\'"][^\'"]{0,500}[\'"];)eval\(gzinflate\(base64_decode\(\3\)\)\);rebirth\(\);eval\(gzinflate\(base64_decode\(hate\(\1,\5\){4};~msi',
            'fast' => '~error_reporting\(\d\);@?set_time_limit\(\d\);(\$\w{1,50})\s?=\s?[\'"]([^\'"]+)[\'"];(\$\w{1,50})\s?=\s?[\'"]([^\'"]+)[\'"];(\$\w{1,50})\s?=\s?[\'"]([^\'"]{0,100})[\'"];(\$\w{1,50}\s?=\s?[\'"][^\'"]{0,500}[\'"];)eval\(gzinflate\(base64_decode\(\$\w{1,50}\)\)\);rebirth\(\);eval\(gzinflate\(base64_decode\(hate\(\$\w{1,50},\$\w{1,50}\){4};~msi',
            'id' => 'evalLoveHateFuncs',
        ],
        [
            'full' => '~function\s?(\w+)\(\){\s?(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];\s?\2\s?=\s?str_rot13\(\2\);\s?(\w+)\(\2\);\s?}\s?function\s?\4\((\$\w+)\){\s?(?:global\s?\$\w+;\s?)?\5\s?=\s?pack\([\'"]H\*[\'"],\5\);\s?(\$\w+)\s?=\s?[\'"]{2};\s?eval\(((?:\6|\5)\.?)+\);\s?}\s?\1\(\);~msi',
            'id'   => 'evalPackStrrot',
        ],
        [
            'full' => '~error_reporting\(\d\);(?:\$\w+=[\'"]\w+[\'"];)?ini_set\([\'"]\w+[\'"],\d\);(?:(\$\w+=\[(?:"[^"]+"=>"[^"]+",?\s*)+\];)|eval\(base64_decode\([\'"]([\w\+=]+)[\'"]\)\);)\$\w+=str_split\([\'"]([}\w|,[=\'\.;\]&]+)[\'"]\);\$\w+=[\'"]{2};foreach\(\$\w+\s{0,50}as\s{0,50}\$\w+\){foreach\((\$\w+)\s{0,50}as\s{0,50}\$\w+\s{0,50}=>\s{0,50}\$\w+\){(?:\$\w+=[\'"]\w+[\'"];\$\w+=[\'"]\w+[\'"];)?if\(\$\w+\s{0,50}==\s{0,50}\(string\)\$\w+\){(?:\$\w+=[\'"]\w+[\'"];\$\w+=[\'"]\w+[\'"];)?\$\w+\s{0,50}\.=\s{0,50}\$\w+;break;}}}(?:eval\([\'"]\?>[\'"]\.gzinflate\(base64_decode\(\$\w+\)\)\);)?~msi',
            'id'   => 'evalArrayVar',
        ],
        [
            'full' => '~((\$\w+)\s*\.?=\s*"[^"]+";\s*)+eval\((\$\w+\s*\.?\s*)+\)~msi',
            'id'   => 'evalVarConcat',
        ],
        [
            'full' => '~(?:\${"[^"]+"}\["[^"]+"\]="[^"]+";)+(?:\${\${"[^"]+"}\["[^"]+"\]}="[^"]+";)+(eval\(htmlspecialchars_decode\(urldecode\(base64_decode\(\${\${"[^"]+"}\["[^"]+"\]}\)\)\)\);)~msi',
            'id' => 'evalVarSpecific',
        ],
        [
            'full' => '~(?:(?:\$\w+=(?:chr\(\d+\)[;.])+)+\$\w+="[^"]+";(\$\w+)=(?:\$\w+[.;])+\s*)?(\$\w+)=\'([^\']+)\';((?:\s*\2=str_replace\(\'[^\']+\',\s*\'\w\',\s*\2\);\s*)+)(?(1)\s*\1\s*=\s*str_replace\(\'[^+]\',\s*\'[^\']+\',\s*\1\);\s*(\$\w+)\s*=\s*[^;]+;";\s*@?\1\(\s*str_replace\((?:\s*array\(\'[^\']+\',\s*\'[^\']+\'\),){2}\s*\5\)\s*\);|\s*\2=base64_decode\(\2\);\s*eval\(\2\);)~msi',
            'id'   => 'evalVarReplace',
        ],
        [
            'full' => '~((\$[^\s=.;]+)\s*=\s*\(?[\'"]([^\'"]+)[\'"]\)?\s*;?\s*)+\s*.{0,10}?(?:error_reporting\(\d\);|@set_time_limit\(\d\);|@|ini_set\([\'"]\w{1,99}[\'"],\s?\d\);\s?){0,5}(?:eval\s*\(|assert\s*\(|echo)\s*([\'"?>.\s]+)?\(?(base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|htmlspecialchars_decode\s*\(|convert_uudecode\s*\()+(\({0,1}[\s"\']?(\$[^\s=\'")]+)?(?:str_replace\((?:.+?,){3}\2?)?[\s"\']?\){0,1})(?:[\'"]?\)+;)+~msi',
            'id'   => 'evalVar',
        ],
        [
            'full' => '~((?:(?:\$\w+=[\'"]\\\\[^\'"]+)[\'"];)+)@(eval\((?:"\?>"\.)?(?:\$\w+\()+[\'"]([^\'"]+)[\'"]\)+;)~msi',
            'id'   => 'evalVarSlashed',
        ],
        [
            'full' => '~function\s*(\w{1,40})\((\$\w{1,40})\)\{(\$\w{1,40})=\'base64_decode\';(\$\w{1,40})=\'gzinflate\';return\s*\4\(\3\(\2\)\);\}\$\w{1,40}=\'[^\']*\';\$\w{1,40}=\'[^\']*\';eval\(\1\(\'([^\']*)\'\)\);~msi',
            'id'   => 'evalFunc',
        ],
        [
            'full' => '~function\s*(\w{1,40})\s*\((\$\w{1,40})\)\s*\{\s*(\$\w{1,40})\s*=\s*"\\\\x62\\\\x61\\\\x73\\\\x65\\\\x36\\\\x34\\\\x5f\\\\x64\\\\x65\\\\x63\\\\x6f\\\\x64\\\\x65";\s*(\$\w{1,40})\s*=\s*"\\\\x67\\\\x7a\\\\x69\\\\x6e\\\\x66\\\\x6c\\\\x61\\\\x74\\\\x65";\s*return\s*\4\s*\(\3\s*\(\2\)\);\s*\}\s*\$\w{1,40}\s*=\s*\"[^\"]*\";\s*\$\w{1,40}\s*=\s*\"[^\"]*\";\s*eval\s*\(\1\s*\(\"([^\"]*)\"\)\);~msi',
            'id'   => 'evalFunc',
        ],
        [
            'full' => '~(\$\w+)\s?=\s?[\'"]@?(([\w."]+\()+[\'"]([\w\/+]+)[\'"])\)+;[\'"]\s?;\s?(\$\w+)\s?=\s?([\w@."]+)\s?;\s?@?(\$\w+)\s?=\s\5\([\'"]+,\s?"\1;"\s?\);\7\([\'"]{2}\);~msi',
            'id'   => 'evalConcatFunc',
        ],
        [
            'full' => '~function\sT_\((\$\w+)\)\s{\s(\$\w+)\s=\s256;\s(\$w2)\s=\s8;\s(\$\w+)\s=\sarray\(\);\s(\$\w+)\s=\s0;\s(\$\w+)\s=\s0;\sfor\s\((\$\w+)\s=\s0;\s\7\s<\sstrlen\(\1\);\s\7\+\+\)\s{\s\5\s=\s\(\5\s<<\s8\)\s\+\sord\(\1\[\7\]\);\s\6\s\+=\s8;\sif\s\(\6\s>=\s\3\)\s{\s\6\s-=\s\3;\s(\$\w+)\[\]\s=\s\5\s>>\s\6;\s\5\s&=\s\(1\s<<\s\6\)\s-\s1;\s\2\+\+;\sif\s\(\2\s>>\s\3\)\s{\s\3\+\+;\s}\s}\s}\s(\$\w+)\s=\srange\("\\\\x0",\s"\\\\377"\);\s(\$\w+)\s=\s\'\';\sforeach\s\(\4\sas\s\7\s=>\s(\$\w+)\)\s{\sif\s\(!isset\(\9\[\11\]\)\)\s{\s(\$\w+)\s=\s(\$\w+)\s\.\s\13\[0\];\s}\selse\s{\s\12\s=\s\9\[\11\];\s}\s\10\s\.=\s\12;\sif\s\(\7\)\s{\s\9\[\]\s=\s\13\s\.\s\12\[0\];\s}\s\13\s=\s\12;\s}\sreturn\s\10;\s}\s(\$_\w+)="[\w\\\\]+";eval\(T_\(\14\("(.*)"\)\)\);~mis',
            'fast' => '~function\sT_\((\$\w+)\)\s{\s(\$\w+)\s=\s256;\s(\$w2)\s=\s8;\s(\$\w+)\s=\sarray\(\);\s(\$\w+)\s=\s0;\s(\$\w+)\s=\s0;\sfor\s\((\$\w+)\s=\s0;\s\7\s<\sstrlen\(\1\);\s\7\+\+\)\s{\s\5\s=\s\(\5\s<<\s8\)\s\+\sord\(\1\[\7\]\);\s\6\s\+=\s8;\sif\s\(\6\s>=\s\3\)\s{\s\6\s-=\s\3;\s(\$\w+)\[\]\s=\s\5\s>>\s\6;\s\5\s&=\s\(1\s<<\s\6\)\s-\s1;\s\2\+\+;\sif\s\(\2\s>>\s\3\)\s{\s\3\+\+;\s}\s}\s}\s(\$\w+)\s=\srange\("\\\\x0",\s"\\\\377"\);\s(\$\w+)\s=\s\'\';\sforeach\s\(\4\sas\s\7\s=>\s(\$\w+)\)\s{\sif\s\(!isset\(\9\[\11\]\)\)\s{\s(\$\w+)\s=\s(\$\w+)\s\.\s\13\[0\];\s}\selse\s{\s\12\s=\s\9\[\11\];\s}\s\10\s\.=\s\12;\sif\s\(\7\)\s{\s\9\[\]\s=\s\13\s\.\s\12\[0\];\s}\s\13\s=\s\12;\s}\sreturn\s\10;\s}\s(\$_\w+)="[\w\\\\]+";eval\(T_\(\14\("(.*)"\)\)\);~mis',
            'id'   => 'evalFuncFunc',
        ],
        [
            'full' => '~(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];\s?(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];\s?(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];\s?(\$\w+)\s?=\s?bin2hex\(\5\);\s?(\$\w+)\s?=\s?hex2bin\(\7\);\s*(?:eval\()+[\'"]\?>[\'"]\.\1\(\3\(\8\)+;~msi',
            'id'   => 'evalBinHexVar',
        ],
        [
            'full' => '~((?:(?:\${"(?:\w{0,10}?\\\\x\w{1,10}){1,100}"}\["\w{0,10}?(?:\\\\x\w{1,10}){1,100}"\]|\$\w+)\s*=\s*[\'"][^\'"]+["\'];)+.*?define.*?)(?:\${)?\$\w{1,50}}?\s*=\s*array\(array\(([\'"][^\)]+[\'"])\)\);(.*?create_function\(.*?array_walk\((?:\${\${"(?:\\\\x\w{1,10}){1,10}"}\["(?:\\\\x\w{1,10}){1,10}"\]}|(?:\${)?\$\w+}?),\s*(?:\${\${"\w?(?:\\\\x\w{1,10}){1,10}"}\["(?:\w?\\\\x\w{1,10}){1,20}"\]}|\$\w+)\);)~msi',
            'fast' => '~create_function\([\'"][^"\']+[\'"],\s*(?:[\'"][^"\']+[\'"]\.?)+.*?\);\s*\$[^=]+=\s*array_walk\((?:\${\${"(?:\\\\x\w{1,10}){1,10}"}\["(?:\\\\x\w{1,10}){1,10}"\]}|(?:\${)?\$\w+}?),\s*(?:\${\${"\w?(?:\\\\x\w{1,10}){1,10}"}\["(?:\w?\\\\x\w{1,10}){1,20}"\]}|\$\w+)\);~msi',
            'id' => 'evalArrayWalkFunc'
        ],
        [
            'full' => '~(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];\s*eval\([\'"]\?>[\'"]\s?\.\s?base64_decode\(strtr\(substr\(\1\s?,(\d+)\*(\d+)\)\s?,\s?substr\(\1\s?,(\d+)\s?,\s?(\d+)\)\s?,\s*substr\(\s?\1\s?,\s?(\d+)\s?,\s?(\d+)(?:\s?\))+;~msi',
            'id' => 'evalSubstrVal'
        ],
        [
            'full' => '~(\$\w{1,50})=[\'"]([^\'"]+)[\'"];\s?\1\s?=\s?base64_decode\(\1\);\s?eval\(gzinflate\(str_rot13\(\1\)+;~msi',
            'id' => 'evalGzStrRotB64',
        ],
        [
            'full' => '~(preg_replace\(["\'](?:/\.\*?/[^"\']+|[\\\\x0-9a-f]+)["\']\s*,\s*)[^\),]+(?:[\)\\\\0-5]+;[\'"])?(,\s*["\'][^"\']*["\'])\)+;~msi',
            'id'   => 'eval',
        ],
        [
            'full' => '~(\$\w{1,40})\s*=\s*[\'"]([^\'"]*)[\'"]\s*;\s*(\$\w{1,40}\s*=\s*(strtolower|strtoupper)\s*\((\s*\1[\[\{]\s*\d+\s*[\]\}]\s*\.?\s*)+\);\s*)+\s*if\s*\(\s*isset\s*\(\s*\$\{\s*\$\w{1,40}\s*\}\s*\[\s*[\'"][^\'"]*[\'"]\s*\]\s*\)\s*\)\s*\{\s*eval\s*\(\s*\$\w{1,40}\s*\(\s*\$\s*\{\s*\$\w{1,40}\s*\}\s*\[\s*[\'"][^\'"]*[\'"]\s*\]\s*\)\s*\)\s*;\s*\}\s*~msi',
            'id'   => 'evalInject',

        ],
        [
            'full' => '~((\$\w+)\s*=\s*(([base64_decode\'\.\s]+)|([eval\'\.\s]+)|([create_function\'\.\s]+)|([stripslashes\'\.\s]+)|([gzinflate\'\.\s]+)|([strrev\'\.\s]+)|([str_rot13\'\.\s]+)|([gzuncompress\'\.\s]+)|([urldecode\'\.\s]+)([rawurldecode\'\.\s]+));\s*)+\$\w+\s*=\s*\$\w+\(\'\',(\s*\$\w+\s*\(\s*)+\'[^\']+\'\)+;\s*\$\w+\(\);~msi',
            'fast' => '~\$\w+\s*=\s*\$\w+\(\'\',(\s*\$\w+\s*\(\s*)+\'[^\']+\'\)+;\s*\$\w+\(\);~msi',
            'id'   => 'createFuncConcat',

        ],
        [
            'full' => '~(\$\w+)\s*=\s*base64_decode\("([^"]+)"\);(\1\s*=\s*ereg_replace\("([^"]+)","([^"]+)",\1\);)+\1=base64_decode\(\1\);eval\(\1\);~msi',
            'id'   => 'evalEregReplace',

        ],
        [
            'full' => '~((\$\w+)\s*=\s*(([base64_decode"\'\.\s]+)|([eval"\'\.\s]+)|([create_function"\'\.\s]+)|([stripslashes"\'\.\s]+)|([gzinflate"\'\.\s]+)|([strrev"\'\.\s]+)|([str_rot13"\'\.\s]+)|([gzuncompress"\'\.\s]+)|([urldecode"\'\.\s]+)([rawurldecode"\'\.\s]+));\s*)+\s*@?eval\(\$[^)]+\)+;~msi',
            'id'   => 'evalWrapVar',

        ],
        [
            'full' => '~(?:\$\{"[^"]+"\}\["[^"]+"\]="[^"]+";)+(?:\$\{\$\{"[^"]+"\}\["[^"]+"\]\}="[^"]+";)+@?eval\s*\(\s*([\'"?>.]+)?@?\s*(base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|eval\s*\()+\(?\$\{\$\{"[^\)]+\)+;~msi',
            'id'   => 'escapes',
        ],
        [
            'full' => '~(\$\w+)\s*=(?:\s*(?:(?:["\'][a-z0-9][\'"])|(?:chr\s*\(\d+\))|(?:[\'"]\\\\x[0-9a-f]+[\'"]))\s*?\.?)+;\s*(\$\w+)\s*=(?:\s*(?:(?:["\'][a-z0-9][\'"])|(?:chr\s*\(\d+\))|(?:[\'"]\\\\x[0-9a-f]+[\'"]))\s*?\.?)+;\s*@?\1\s*\(@?\2\s*\([\'"]([^\'"]+)[\'"]\)+;~msi',
            'id'   => 'assert',
        ],
        [
            'full' => '~eval\s*\(str_rot13\s*\([\'"]+\s*(?:.+(?=\\\\\')\\\\\'[^\'"]+)+[\'"]+\)+;~msi',
            'id'   => 'evalCodeFunc',
        ],
        [
            'full' => '~\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\'](\w+)[\'"];\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\']\2[\'"];\${\$\{"GLOBALS"\}\[[\'"]\3[\'"]\]}=[\'"]([^\'"]+)[\'"];eval.{10,50}?\$\{\$\{"GLOBALS"\}\[[\'"]\1[\'"]\]\}\)+;~msi',
            'id'   => 'evalVarVar',
        ],
        [
            'full' => '~(\$\w+)=[\'"][^"\']+[\'"];(\$\w+)=strrev\(\'edoced_46esab\'\);eval\(\2\([\'"][^\'"]+[\'"]\)+;~msi',
            'id'   => 'edoced_46esab',
        ],
        [
            'full' => '~(\$\w+)=strrev\([\'"](?:|ed|oc|_|4|6|es|ab|(?:"\."))+[\'"]\);\s*(\$\w+)=strrev\([\'"](?:|et|al|fn|iz|g|(?:"\."))+[\'"]\);\s?@?eval\(\2\(\1\([\'"]([\w\/\+=]+)[\'"]\)\)\);~msi',
            'id'   => 'edoced_46esab_etalfnizg',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"((?:[^"]|(?<=\\\\)")*)";(\$\w+)\s*=\s*(\1\[\d+\]\.?)+;(\$\w+)\s*=\s*[^;]+;(\$\w+)\s*=\s*"[^"]+";\$\w+\s*=\s*\5\."[^"]+"\.\6;\3\((\1\[\d+\]\.?)+,\s*\$\w+\s*,"\d+"\);~smi',
            'fast' => '~(\$\w+)\s*=\s*"((?:[^"]|(?<=\\\\)"){0,1000})";(\$\w+)\s*=\s*(\1\[\d+\]\.?)+;(\$\w+)\s*=\s*[^;]+;(\$\w+)\s*=\s*"[^"]+";\$\w+\s*=\s*\5\."[^"]+"\.\6;\3\((\1\[\d+\]\.?)+,\s*\$\w+\s*,"\d+"\);~smi',
            'id'   => 'eval2',
        ],
        [
            'full' => '~(?:\${"\\\\x[\\\\\w]+"}\["\\\\x[\\\\\w]+"\]\s?=\s?"[\w\\\\]+";){1,10}\${\${"\\\\x[\\\\\w]+"}\["[\\\\\w]+"\]}\s?=\s?"\w{1,100}";\${\${\${"\\\\x[\\\\\w]+"}\["[\\\\\w]+"\]}\s?}="(\\\\x[^"]+)";eval\(((?|str_rot13\(|gzinflate\(|base64_decode\(){1,10})\(\${\${"\\\\x[\\\\\w]+"}\["[\\\\\w]+"\]}\){1,5};~msi',
            'id'   => 'evalEscapedCharsContent',
        ],
        [
            'full' => '~@?(eval|echo|(\$\w+)\s*=\s*create_function)(?:\/\*+\/)?\s*\((\'\',)?\s*([\'"][?>\s]+[\'".\s]+)?\s*\(?\s*@?\s*(?:base64_decode\s*\(|pack\s*\(\'H\*\',|convert_uudecode\s*\(|htmlspecialchars_decode\s*\(|gzdecode\s*\(|stripslashes\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|unserialize\s*\(|eval\s*\(|hex2bin\()+.*?[^\'");]+((\s*\.?[\'"]([^\'";]+[\'"]*\s*)+|,\s*true)?\s*[\'"\)]+)+\s*;?(\s*\2\(\);)?~msi',
            'id'   => 'eval',
        ],
        [
            'full' => '~eval\s*/\*[\w\s\.:,]+\*/\s*\([^\)]+\)+;~msi',
            'fast' => '~eval\s*/\*[\w\s\.:,]+\*/\s*\(~msi',
            'id'   => 'eval',
        ],
        [
            'full' => '~((?:\$\w+\s?=\s?(?:base64_decode|str_rot13)\([\'"][^\'"]+[\'"]\);)+)\s?(@?eval\((?:(?:\w+\()*\$\w+\(?)+(?:.*?)?\)+;)~msi',
            'id'   => 'evalFuncVars',
        ],
        [
            'full' => '~eval\("\\\\145\\\\166\\\\141\\\\154\\\\050\\\\142\\\\141\\\\163[^\)]+\)+;~msi',
            'fast' => '~eval\("\\\\145\\\\166\\\\141\\\\154\\\\050\\\\142\\\\141\\\\163~msi',
            'id'   => 'evalHex',
        ],
        [
            'full' => '~eval\s*\("\\\\x?\d+[^\)]+\)+;(?:[\'"]\)+;)?~msi',
            'fast' => '~eval\s*\("\\\\x?\d+~msi',
            'id'   => 'evalHex',
        ],
        [
            'full' => '~(\$\w+)\s=\s(["\']?[\w\/\+]+["\']?);\s(\$\w+)\s=\s((?:str_rot13\(|rawurldecode\(|convert_uudecode\(|gzinflate\(|str_rot13\(|base64_decode\(|rawurldecode\(|)+\1\)\)+);\secho\s(eval\(\3\);)~msi',
            'id'   => 'echoEval',
        ],
        [
            'full' => '~if\(!function_exists\([\'"](\w+)[\'"]\)\){function\s?\1\((\$\w+)\){(\$\w+)=array\((?:\'(\d+)\',)?\'([^\']+)\',\'([^\']+)\',\2\);for\((\$\w+)=0;\7<[34];\7\+\+\){for\((\$\w+)=0;\8<strlen\(\3\[\7\]\);\8\+\+\)\s?\3\[\7\]\[\8\]\s?=\s?chr\(ord\(\3\[\7\]\[\8\]\)-(?:\(\7\?\3\[\8\s?xor\s?\8\]:1\)|1)\);if\(\7==[21]\)\s?\3\[[32]\]=\3\[[01]\]\(\3\[[21]\]\(\3\[[32]\]\)\);}\s?return\s?\3\[[32]\];}(\$\w+)=["\']([\w\+\/=]+)["\'];(\$\w+)=[\'"]\1[\'"];(\$\w+)=\11\([\'"]([^\'"]+)[\'"]\);\$\w+=@?\12\(\'\',\11\(\9\)\);\$\w+\(\);}~msi',
            'id'   => 'evalCreateFunc',
        ],
        [
            'full' => '~(\$\w{1,1000})=[\'"]([\'"\w/\+=]+)[\'"];(\$\w{1,3000}=(?:base64_decode|gzinflate|convert_uudecode|str_rot13)\(\$\w{1,3000}\);){1,100}eval\((\$\w{1,3000})\);~msi',
            'id'   => 'evalAssignedVars',
        ],
        [
            'full' => '~(?:\$_{1,50}\s*=\s*[^;]{2,200}\s*;\s*)+(?:\$_{1,50}\s*=\s*\$_{1,50}\([^\)]+\);\s*|(?:if\(!function_exists\(\'[^\']+\'\)\){function\s\w{1,50}\(\$\w{1,50},\$\w{1,50}\){return\s?eval\("return function\(\$\w{1,50}\){{\$\w{1,50}}};"\);}}\s*)?)+(?:\$_{1,50}\s*=\s*\'[^\']+\';\s*)?(?:\s*(\$_{1,50}\s*=\s*)?\$_+\([^)]*\)+;\s*)+(?:echo\s*\$_{1,50};)?~msi',
            'id'   => 'seolyzer',
        ],
        [
            'full' => '~(\$\w+)="((?:[^"]|(?<=\\\\)")*)";(\s*\$GLOBALS\[\'\w+\'\]\s*=\s*(?:\${)?(\1\[\d+\]}?\.?)+;\s*)+(.{0,400}\s*\1\[\d+\]\.?)+;\s*}~msi',
            'fast' => '~(\$\w+)="((?:[^"]|(?<=\\\\)"){0,1000})";(\s*\$GLOBALS\[\'\w+\'\]\s*=\s*(?:\${)?(\1\[\d+\]}?\.?)+;\s*)+(.{0,400}\s*\1\[\d+\]\.?)+;\s*}~msi',
            'id'   => 'subst2',
        ],
        [
            'full' => '~(\$\w{1,50}\s*=\s*"[^"]{1,1000}";\s*)+(\$\w{1,50}\s*=\s*\$?\w{1,50}\("\w{1,50}"\s*,\s*""\s*,\s*"\w{1,50}"\);\s*)+\$\w{1,50}\s*=\s*\$\w{1,50}\("",\s*\$\w{1,50}\(\$\w{1,50}\("\w{1,50}",\s*"",(\s*\$\w{1,50}\.?)+\)+;\$\w{1,50}\(\);~msi',
            'id'   => 'strreplace',
        ],
        [
            'full' => '~\$\w{1,50}\s?=\s?(?:\'[^\']{1,500}\'|"[^}]{1,500}}");\s?\$\w{1,50}\s?=\s?str_replace\([\'"]\w{1,50}[\'"],\s?[\'"][\'"],\s?["\']\w{1,100}[\'"]\);\s?(?:\$\w{1,50}\s?=\s?(?:\'[^\']{1,500}\'|"[^\s]{1,500}?");\s){1,15}.*?\$\w{1,50}\s?=\s?str_replace\((?:\'[^\']{1,100}\'|"[^"]{1,100}?"),\s?\'\',\s?(?:\$\w{1,50}\s?\.?\s?){1,50}\);\s?\$\w{1,50}\s?=\s?\$\w{1,50}\(\'\',\s?\$\w{1,50}\);\s?\$\w{1,50}\(\);~msi',
            'id'   => 'strreplace',
        ],
        [
            'full' => '~function\s(\w{1,50})\((\$\w{1,50}),\$\w{1,50}\)\s?{if\(file_exists[^}]+}(\$\w{1,50})\s?=\s?str_replace\(array\(base64_decode\(\'([^\']+)\'\),base64_decode\(\'([^\']+)\'\)\),array\(base64_decode\(\'([^\']+)\'\),base64_decode\(\'([^\']+)\'\)\),\2\);(\$\w{1,50})\s?=\s?strrev[^;]+;(\$\w{1,50})\s?=\s?\8\(\3\);(\$\w{1,50})\s?=\s?strrev[^;]+;return@?\10\(\9\);}if.*?exit;}\s?((\$\w{1,50})\s?=\s?base64_decode\(\'([^\']+)\'\);preg_match\(base64_decode\(\'[^\']+\'\),\12,(\$\w{1,50})\);(\$\w{1,50})\s?=\s?\14\[1\];(\$\w{1,50})\s?=\s?\1\(\15,\$\w{1,50}\);if\(isset\(\16\)\){eval\(\16\);})~msi',
            'id' => 'pregB64FuncImgStr',
        ],
        [
            'full' => '~@?echo\s*([\'"?>.\s]+)?@?\s*(base64_decode\s*\(|stripslashes\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|eval\s*\()+[\s\/\'"].*?[^\'")]+((\s*\.?[\'"]([^\'";\$]+\s*)+)?\s*[\'"\);]+)+~msi',
            'id'   => 'echo',
        ],
        [
            'full' => '~(\$\w+)="([^"]+)";\s*(\$\w+)=strtoupper\s*\((\1\[\d+\]\s*\.?\s*)+\)\s*;\s*if\(\s*isset\s*\(\${\s*\3\s*}\[\d*\s*\'\w+\'\s*\]\s*\)\s*\)\s*{eval\(\${\3\s*}\[\'\w+\']\s*\)\s*;}~smi',
            'fast' => '~(\$\w+)="([^"]+)";\s*(\$\w+)=strtoupper\s*\((\1\[\d+\]\s*\.?\s*)+\)\s*;\s*if\(\s*isset\s*\(\${\s*\3\s*}\[\d*\s*\'\w+\'\s*\]\s*\)\s*\)\s*{eval\(\${\3\s*}\[\'\w+\']\s*\)\s*;}~smi',
            'id'   => 'strtoupper',
        ],
        [
            'full' => '~(\$\w+)="[^"]+";\s*(\$\w+)=str_ireplace\("[^"]+","",\1\);(\$\w+)\s*=\s*"[^"]+";\s*function\s*(\w+)\((\$\w+,?)+\){\s*(\$\w+)=\s*create_function\(\'\',\$\w+\);\s*array_map\(\6,array\(\'\'\)+;\s*}\s*set_error_handler\(\'\4\'\);(\$\w+)=\2\(\3\);user_error\(\7,E_USER_ERROR\);\s*if\s*.+?}~msi',
            'id'   => 'errorHandler',
        ],
        [
            'full' => '~(\$\w+)=strrev\(str_ireplace\("[^"]+","","[^"]+"\)\);(\$\w+)="([^"]+)";eval\(\1\(\2\)+;}~msi',
            'id'   => 'evalIReplace',
        ],
        [
            'full' => '~error_reporting\((?:0|E_ALL\^E_NOTICE)\);ini_set\("display_errors",\s*[01]\);if\(!defined\(\'(\w+)\'\)\){define\(\'\1\',__FILE__\);if\(!function_exists\("([^"]+)"\)\){function [^(]+\([^\)]+\).+?eval\(""\);.+?;}?eval\(\$[^\)]+\)\);[^\)]+\)+.*?;return\s*\$[^;]+;\s*\?>([^;]+);~msi',
            'id'   => 'PHPJiaMi',
        ],
        [
            'full' => '~\$\w+=0;(\$GLOBALS\[\'\w+\'\])\s*=\s*\'([^\']+)\';\s*(\$\w+)=pack\(\'H\*\',substr\(\1,\s*([-\d]+)\)\);if\s*\(!function_exists\(\'(\w+)\'\)\){function\s*\5\(\$\w+,\s*\$\w+\){\$\w+=\1;\s*\$d=pack\(\'H\*\',substr\(\1,\s*\4\)\);\s*return\s*\$\w+\(substr\(\$\w+,\s*\$\w+,\s*\$\w+\)\);}};eval\(\3\(\'[^\']+\'\)\);~msi',
            'id'   => 'substr',
        ],
        [
            'full' => '~(?:\$\{\'GLOBALS\'\}\[\'\w+\'\]=\'_F\';)?\$(?:_F|\{\$\{\'GLOBALS\'\}\[\'\w+\'\]\})=_{1,2}(?:FILE|hex)_{1,2};(?:\$\{\'GLOBALS\'\}\[\'\w+\'\]=\'_X\';)?\$(?:_X|\{\$\{\'GLOBALS\'\}\[\'\w+\'\]\})=["\']([^\'"]+)[\'"];\s*(?:\$[_\w]+\.=[\'"][\w\+\/=]+[\'"];){0,30}\$_\w+=base64_decode\(\$_X\);\$_X=strtr\(\$_X,\'([^\']+)\',\'([^\']+)\'\);\$_R=@?(?:(str_replace)|(ereg_replace)|(preg_replace))\(\'\~?__FILE__\~?\',"\'".\$_F."\'",\$_X\);eval\(\$_R\);\$_R=0;\$_X=0;~msi',
            'fast' => '~\$_\w+=base64_decode\(\$_X\);\$_X=strtr\(\$_X,\'([^\']+)\',\'([^\']+)\'\);\$_R=@?(?:(str_replace)|(ereg_replace)|(preg_replace))\(\'\~?__FILE__\~?\',"\'".\$_F."\'",\$_X\);eval\(\$_R\);\$_R=0;\$_X=0;~msi',
            'id'   => 'LockIt2',
        ],
        [
            'full' => '~(?:@error_reporting\(\d+\);\s*@set_time_limit\(\d+\);)?\s*(\$\w+)=([\s\'\w\/+=]+);\s*(\$\w+)=(__FILE__);\s*\1=gzinflate\(str_rot13\(base64_decode\(\$tr\)\)\);\1=strtr\(\1,\'([^\']+)\'\s*,\'([^\']+)\'\);(\$_R)=@?ereg_replace\(\'\~?\4\~?\',"\'".\3."\'",\1\);eval\(\7\);\7=0;\1=0;~msi',
            'fast' => '~(\$\w+)=([\s\'\w\/+=]+);\s*(\$\w+)=(__FILE__);\s*\1=\w+\(\w+\(\w+\(\$tr\)\)\);\1=\w+\(\1,\'([^\']+)\'\s*,\'([^\']+)\'\);(\$_R)=@?\w+\(\'\~?\4\~?\',"\'".\3."\'",\1\);\w+\(\7\);\7=0;\1=0;~msi',
            'id'   => 'anaski',
        ],
        [
            'full' => '~\$\w+="[^"]+";\$l+=0;\$l+=\'base64_decode\';\$l+=0;eval\([^\^]+\^[\dx]+\);}eval\(\$l+\("[^"]+"\)+;eval\(\$l+\);return;~msi',
            'id'   => 'custom1',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"(\w{32})";\s*(\$\w+)\s*=\s*array\s*\(\);\s*(\3\[\d+\]\s*=\s*"[^"]+";\s*)+\s*(\$\w+)\s*=\s*"base64_decode";\s*\$\w+\s*=\s*(\w+)\s*\(\3,\1\);function\s*\6\(\s*.{200,500}return\s*\$\w+;\s*}\s*eval\s*\(\5\s*\(\$\w+\)\);~msi',
            'id'   => 'custom2',
        ],
        [
            'full' => '~\$\w+=\'=+\s*Obfuscation provided by Unknowndevice64 - Free Online PHP Obfuscator\s*(?:http://www\.ud64\.com/)?\s*=+\';\s*(\$ud64_c[o0]m="[\\\\0-9a-z\."]+;)+\$\w+=(\$ud64_c[o0]m\()+"([^"]+)"\)+;@eval\(\$ud64_c[o0]m\(\'[^\']+\'\)+;~msi',
            'id'   => 'ud64',
        ],
        [
            'full' => '~(\$[\w_]+=("[\\\\\\\\\w]+"\.?)+;)+\$\w+=(?:\$\w+\()+"([\w\/\+=]+)"\)+;@eval\(\$\w+\(\'.*?\'\)+;~msi',
            'id'   => 'ud64',
        ],
        [
            'full' => '~\$\w+=__FILE__;\$\w+=fopen\(\$\w+,\'rb\'\);fread\(\$\w+,(\d+)\);\$\w+=explode\("\\\\t",base64_decode\(fread\(\$\w+,(\d+)\)+;\$\w+=\$\w+\[[\d+]\];[\$l1=\d{}\.;\(\)\[\]]+eval\(\$\w+\(\'[^\']+\'\)+;\s*return\s*;\?>[\w=\+]+~msi',
            'id'   => 'qibosoft',
        ],
        [
            'full' => '~(\$\w+)=base64_decode\("([^"]+)"\);\s*eval\("return\s*eval\(\\\\"\1\\\\"\);"\)~msi',
            'id'   => 'evalReturn',
        ],
        [
            'full' => '~(?:\$[0O]+\[[\'"](\w+)[\'"]\]\.?="[\\\\\w]+";)+(?:\$[0O]+\[[\'"]\w+[\'"]\]\.?=\$[0O]+\[[\'"]\w+[\'"]\]\([\'"][\d\(]+[\'"](,__FILE__)?\);)+@eval\((?:\$[0O]+\[[\'"]\w+[\'"]\]\()+"([^"]+)"\)+;~mis',
            'fast' => '~(?:\$[0O]+\[[\'"](\w+)[\'"]\]\.?="[\\\\\w]+";)+(?:\$[0O]+\[[\'"]\w+[\'"]\]\.?=\$[0O]+\[[\'"]\w+[\'"]\]\([\'"][\d\(]+[\'"](,__FILE__)?\);)+@eval\((?:\$[0O]+\[[\'"]\w+[\'"]\]\()+"([^"]+)"\)+;~mis',
            'id'   => 'evalChars',
        ],
        [
            'full' => '~<\?php\s+((\$GLOBALS\[\s*[\'"]\w+[\'"]\s*\])\s*=\s*base64_decode\("([^"]*)"\);)+\s*\?><\?php\s.+\2.+exit;\s}\sfunction\s\w+\(\)\s{\sreturn\sarray\(\s\'favicon\'\s=>\s\'[^\']+\',\s+\'sprites\'\s=>\s\'[^\']+\',\s\);\s}~msi',
            'id'   => 'globalsBase64',
        ],
        [
            'full' => '~(\$\w+=strrev\("[^"]+"\);)+eval\((\$\w+\()+"[^"]+"\)+;~mis',
            'fast' => '~(\$\w+=strrev\("[^"]+"\);)+eval\((\$\w+\()+"[^"]+"\)+;~mis',
            'id'   => 'strrevVarEval',
        ],
        [
            'full' => '~\$\w+=basename/\*\w+\*/\(/\*\w+\*/trim/\*\w+\*/\(.+?(\$\w+)=.+\1.+?;~msi',
            'id'   => 'comments',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*(base64_decode\s*\(+|gzinflate\s*\(+|strrev\s*\(+|str_rot13\s*\(+|gzuncompress\s*\(+|convert_uudecode\s*\(+|urldecode\s*\(+|rawurldecode\s*\(+|htmlspecialchars_decode\s*\(+)+"([^"]+)"\)+;\s*@?eval\(([\'"?>.\s]+)?\1\);~',
            'fast' => '~(\$\w+)\s*=\s*(base64_decode\s*\(+|gzinflate\s*\(+|strrev\s*\(+|str_rot13\s*\(+|gzuncompress\s*\(+|convert_uudecode\s*\(+|urldecode\s*\(+|rawurldecode\s*\(+|htmlspecialchars_decode\s*\(+)+"([^"]+)"\)+;\s*@?eval\(([\'"?>.\s]+)?\1\);~',
            'id'   => 'varFuncsEval',
        ],
        [
            'full' => '~((\$\w+)="";\$\w+\s*\.=\s*"[^;]+;\s*)+(?:(?:\$\w+)?="";)?eval\((\s*\$\w+\s*\.)+\s*"[^"]+(?:"\);)+~msi',
            'id'   => 'evalConcatVars',
        ],
        [
            'full' => '~<\?php\s*defined\(\'[^\']+\'\)\s*\|\|\s*define\(\'[^\']+\',__FILE__\);(global\s*\$[^;]+;)+\s*(if\(!function_exists\(\'([^\']+)\'\)\){\s*function\s*[^\)]+\(\$[^,]+,\$[^=]+=\'\'\){\s*if\(empty\(\$[^\)]+\)\)\s*return\s*\'\';\s*\$[^=]+=base64_decode\(\$[^\)]+\);\s*if\(\$[^=]+==\'\'\)\s*return\s*\~\$[^;]+;\s*if\(\$[^=]+==\'-1\'\)\s*@[^\(]+\(\);\s*\$[^=]+=\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\(\$[^\)]+\);\s*\$[^=]+=\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\(\$[^,]+,\$[^,]+,\$[^\)]+\);\s*return\s*\$[^^]+\^\$[^;]+;\s*}}\s*)+(\$[^\[]+\["[^"]+"]=[^\(]+\(\'[^\']+\',\'[^\']*\'\);\s*)+(\$[^\[]+\[\'[^\']+\'\]=\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\([^\)]*\)+;\s*)+return\(eval\(\$[^\[]+\[\'[^\']+\'\]\)+;\s*\?>\s*#!/usr/bin/php\s*-q\s*(\s*[^\s]+)+~msi',
            'fast' => '~<\?php\s*defined\(\'[^\']{10,30}\'\)\s*\|\|\s*define\(\'[^\']{10,30}\',__FILE__\);(global\s*\$[^;]{10,30};)+\s*if\(!function_exists\(\'([^\']+)\'\)\){\s*function\s*[^\)]+\(\$[^,]{10,30},\$[^=]{10,30}=\'\'\){\s*if\(empty\(\$[^\)]+\)\)\s*return\s*\'\';\s*\$[^=]{10,30}=base64_decode~msi',
            'id'   => 'OELove',
        ],
        [
            'full' => '~(?:\$\w+\s*=(\s*(\d+)\+)*\d+;\s*)?(\$\w+="[^"]+";\s*)+\s*(?:\$\w+\s*=(?:\s*(?:\d+)\+)*\s*\d+;\s*)?(\$\w+)\s*=\s*\w+\(\'[^\']+\',\s*\$\w+,\s*\'[^\']+\'\);.+?\4\("[^"]+"\);\s*\$\w+\s*=\s*\4;\s*(\$\w+="[^"]+";\s*)+.+?\$\w+\(\$\w+,\$\w+\("",\s*\$\w+\(\$\w+\(\$\w+\(\$\w+\(\$\w+,\s*"(\d+)"\)+,\$\w+\);.+function \w+\((\$\w+),\s*\$\w+,\s(\$\w+)\)\s{\8\s=\s\8\s\.\s\8;.+return \7;\s*}~msi',
            'fast' => '~(\$\w+)\s*=\s*\w+\(\'[^\']+\',\s*\$\w+,\s*\'[^\']+\'\);.+?\1\("[^"]+"\);\s*\$\w+\s*=\s*\1;\s*(\$\w+="[^"]+";\s*)+~msi',
            'id'   => 'Obf_20200402_1',
        ],
        [
            'full' => '~(?:\$\w+\s*=\s*"[^"]+";\s*)?(?:((?:\$\w+\s*=\s*\'[^\']+\';\s*)+)(\$\w+=(?:\$\w+\.?)+);)?function\s(\w+)\((\$\w+),\s*(\$\w+),\s*(\$\w+)\)\s*{\s*return\s*([\'\. ]*(\4|\5|\6)[\'\. ]*)+;\s*}\s*(?:\$\w+\s*=\s*"[^"]+";)?(\s*\$\w+\s*=\s*\3\((((\'\')|(\$\w+)|(\$\w+[\[\{]\d+[\]\}](\.\'\')?)|(\$\w+[\[\{]\d+[\]\}]\.\$\w+[\[\{]\d+[\]\}]))\s*,?\s*)+\);\s*)+\s*\$\w+\s*=\s*\3[^"]+[^\']+\'([^\']+)\'"[^/]+\'//\'\)+;~msi',
            'fast' => '~function\s(\w+)\((\$\w+),\s*(\$\w+),\s*(\$\w+)\)\s*{\s*return\s*([\'\. ]*(\2|\3|\4)[\'\. ]*)+;\s*}\s*(?:\$\w+\s*=\s*"[^"]+";)?(\s*\$\w+\s*=\s*\1\((((\'\')|(\$\w+)|(\$\w+[\[\{]\d+[\]\}](\.\'\')?)|(\$\w+[\[\{]\d+[\]\}]\.\$\w+[\[\{]\d+[\]\}]))\s*,?\s*)+\);\s*)+\s*\$\w+\s*=\s*\1[^"]+[^\']+\'([^\']+)\'"[^/]+\'//\'\)+;~msi',
            'id'   => 'Obf_20200402_2',
        ],
        [
            'full' => '~(?:function\s*\w{1,50}\(\$\w{1,50},\s*\$\w{1,50}\)\s*\{(?:\s*\$\w{1,50}\s*=\s*(?:md5\(\$\w{1,50}\)|\d+|base64_decode\(\$\w{1,50}\)|strlen\(\$\w{1,50}\)|\'\');\s*)+\s*for\s*\(\$\w{1,50}\s*=\s\d+;\s*\$\w{1,50}\s*<\s*\$len;\s*\$\w{1,50}\+\+\)\s*\{\s*if\s*\(\$\w{1,50}\s*==\s*\$\w{1,50}\)\s*\{\s*\$\w{1,50}\s*=\s*\d+;\s*}\s*\$\w{1,50}\s*\.=\s*substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\);\s*\$\w{1,50}\+\+;\s*\}(?:\s*\$\w{1,50}\s*=\s*\'\';)?\s*for\s*\(\$\w{1,50}\s*=\s*\d+;\s*\$\w{1,50}\s*<\s*\$\w{1,50};\s*\$\w{1,50}\+\+\)\s*{\s*if\s*\(ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\s*<\s*ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\)\s*\{\s*\$\w{1,50}\s*\.=\s*chr\(\(ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\s*\+\s*\d+\)\s*-\s*ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\);\s*}\s*else\s*{\s*\$\w{1,50}\s*\.=\s*chr\(ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\s*-\s*ord\(substr\(\$\w{1,50},\s*\$\w{1,50},\s*\d+\)\)\);\s*}\s*}\s*return\s*\$\w{1,50};\s*\}\s*|\$\w{1,50}\s*=\s*"([^"]+)";\s*){2}\s*\$\w{1,50}\s*=\s*"([^"]+)";\s*\$\w{1,50}\s*=\s*\w{1,50}\(\$\w{1,50},\s*\$\w{1,50}\);\s*eval\(\$\w{1,50}\);~msi',
            'id'   => 'Obf_20200414_1',
        ],
        [
            'full' => '~(?:\$\w+\s*=\s*\'\w+\';)?\s*(\$\w+)\s*=\s*urldecode\(\'[%0-9a-f]+\'\);(\s*(\$\w+)\s*=(\s*\1\{\d+\}\.?)+;)+\s*(\$\w+)\s*=\s*"[^"]+"\.\3\("[^"]+"\);\s*eval\(\5\);~msi',
            'fast' => '~(\$\w+)\s*=\s*urldecode\(\'[%0-9a-f]+\'\);(\s*(\$\w+)\s*=(\s*\1\{\d+\}\.?)+;)+\s*(\$\w+)\s*=\s*"[^"]+"\.\3\("[^"]+"\);\s*eval\(\5\);~msi',
            'id'   => 'Obf_20200421_1',
        ],
        [
            'full' => '~(\$\w+)=\'([^\']+)\';(\$\w+)=str_rot13\(gzinflate\(str_rot13\(base64_decode\(\1\)\)\)\);eval\(\3\);~msi',
            'id'   => 'SmartToolsShop',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*\("\?>"\.gzuncompress\(base64_decode\("[^"]+"\)\)\);\s*@?eval\(\1\);~msi',
            'id'   => 'Obf_20200504_1',
        ],
        [
            'full' => '~(\$\w+)=base64_decode\(\'[^\']+\'\);\s*eval\(\1\);~mis',
            'fast' => '~(\$\w+)=base64_decode\(\'[^\']+\'\);\s*eval\(\1\);~mis',
            'id'   => 'Obf_20200507_1',
        ],
        [
            'full' => '~(?:error_reporting\(0\);\s*ini_set\("max_execution_time",0\);\s*(?:/\*.*?\*/)?\s*)?(\$\w+)=\s*\[(("."=>".",?\s*)+)];\s*(\$\w+)=str_split\("([^"]+)"\);\s*(?:\$\w+="";)?\s*foreach\(\4\s*as\s*(\$\w+)\)\s*{\s*foreach\(\s*\1\s*as\s*(\$\w+)=>(\$\w+)\)\s*{\s*if\(\6==\(string\)\8\)\s*\{\s*\$\w+\.=\7;\s*break;\s*}\s*}\s*}~msi',
            'fast' => '~(\$\w+)=\s*\[(("."=>".",?\s*)+)];\s*(\$\w+)=str_split\("([^"]+)"\);\s*(?:\$\w+="";)?\s*foreach\(\4\s*as\s*(\$\w+)\)\s*{\s*foreach\(\s*\1\s*as\s*(\$\w+)=>(\$\w+)\)\s*{\s*if\(\6==\(string\)\8\)\s*\{\s*\$\w+\.=\7;\s*break;\s*}\s*}\s*}~msi',
            'id'   => 'Obf_20200507_4',
        ],
        [
            'full' => '~assert\("[eval"\.]+\([base64_decode\."]+\(\'([^\']+)\'\)\)"\);~msi',
            'id'   => 'Obf_20200507_5',
        ],
        [
            'full' => '~parse_str\s*\(\'([^\']+)\'\s*,\s*(\$\w+)\)\s*;(\2\s*\[\s*\d+\s*\]\s*\(\s*)+\'[^\']+\'\s*\),\s*array\(\s*\),\s*array\s*\(\s*\'[^\']+\'\s*\.(\2\[\s*\d+\s*\]\()+\'([^\']+)\'\s*[\)\s]+\.\'//\'[\s\)]+;~msi',
            'id'   => 'Obf_20200513_1',
        ],
        [
            'full' => '~(\$\w+)=strrev\("[base64_decode"\.]+\);eval\(\1\(\'([^\']+)\'\)\);~msi',
            'id'   => 'Obf_20200526_1',
        ],
        [
            'full' => '~error_reporting\(0\);define\(\'\w+\',\s*__FILE__\);define\(\'\w+\',\s*fopen\(__FILE__,\s*\'r\'\)\);fseek\(\w+,\s*__COMPILER_HALT_OFFSET__\);((\$\w+="\\\\x[0-9a-f]+";)+(\$\w+="[^"]+";)+eval\("\?>"\.(\$\w+\()+"([^"]+)"\)+;)+(?:/\*\w+\*/)?__halt_compiler\(\);[\w#|>^%\[\.\]\\\\/=]+~msi',
            'id'   => 'Obf_20200527_1',
        ],
        [
            'full' => '~(\$\w+)=strrev\("[base64_decode]+"\)\.str_replace\(\'(\w+)\',\'\',\'\w+\'\);\s*eval\(\1\(\$\w+\)\);~msi',
            'id'   => 'Obf_20200602_1',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"([^"]+)";\s*(\$\w+)\s*=\s*base64_decode\(\1\);\s*eval\(\3\);~msi',
            'id'   => 'Obf_20200720_1',
        ],
        [
            'full' => '~[\'".]+(\$\w+\s*=\s*[\'"]\w+[\'"];)+(\$\w+=\$\w+[\'.]+\$\w+;)+(\$\w+=(str_rot13|base64_decode|gzinflate)\(\$\w+\);)+eval\(\$\w+\);~msi',
            'id'   => 'flamux',
        ],
        [
            'full' => '~function\s*(\w+)\(\)\{\s*return\s*"([^"]+)";\s*\}\s*eval\("([^"]+)"\.\1\(\)\."([^"]+)"\);~msi',
            'id'   => 'bypass',
        ],
        [
            'full' => '~(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+(echo)\s*"(?:[<\w\\\\>\/\s={:}#]+);(?:[\\\\\w\-:]+;)+(?:[\\\\\w}:{\s#]+;)+(?:[\\\\\w}:{#\-\s]+;)+[\\\\\w}<\/]+";\$\w+=["\\\\\w]+;(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+\$\w+=["\\\\\w]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";error_reporting\(\d\);\$\w+=["\\\\\w]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\$\w+=["\\\\\w]+;set_time_limit\(\d\);\$\w+=["\\\\\w]+;(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+(if\(empty\()[\$_\w\["\\\\\]]+\)\){\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\w()]+;(}else{)\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;}chdir\(\${\$\w+}\);\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=htmlentities\(\$[_\w\["\\\\\].?]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);\1[<\\\\\w>\/"]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";(?:\$\w+=["\w\\\\]+;)+(?:\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;)+\$\w+=["\w\\\\]+;\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1["\\\\\w<>=\s\'.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w=\s\/<>]+;(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+\1["<\\\\\w\s\'.\${}>\/]+;\1["<\\\\\w>\s\'.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."&\w\\\\\'<\/]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\$\w+=["\\\\\w]+;\1["<\\\\\w>\s=\'.\${}&\/]+;(?:\1["<\\\\\w>\/]+;)+\$\w+=["\\\\\w]+;\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";switch\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\){case"[\w\\\\\s]+":(?:\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;)+\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){(?:\$\w+=["\\\\\w]+;)+(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=fopen\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},"\w"\);\$\w+=["\\\\\w]+;\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=(?:(?|fread|filesize)\(\${\$\w+},?)+\)\);\${\$\w+}=str_replace\("[\w\\\\\s]+",[<\w\\\\>"]+,\${\$\w+}\);\1["\\\\\w<>=\s\'.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w=\s\/<>&\${}\']+;\1["\\\\\w\s.:]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\."[\w\\\\\s]+";\1["\\\\\w\s\'=]+\.\${\$\w+}\.["<\w\\\\>]+;\1["<\\\\\w>\s=\'\/;]+\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";(?:\$\w+=["\w\\\\]+;)+\${\$\w+}=fopen\(\${\$\w+},"\w"\);if\(fwrite\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\s\\\\\w]+;\3\1["\\\\\w\s.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\\\\\w]+;}}fclose\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);(break;case")[\w\\\\\s]+":\${\$\w+}=[\$_\w\["\]\\\\]+;if\(unlink\([\${}\w]+\)\){\1\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\.["\s\w\\\\.>]+;\3\$\w+=["\w\\\\]+;\1["\\\\\w\s.${}<]+;}\4[\w\\\\\s]+":(?:\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;)+\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1["<\w\\\\\s=.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}.["\\\\\w&.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w\s=]+;(?:\1["\w\\\\:\s\'><=\/]+;)+\3(?:\$\w+=["\w\\\\]+;)+if\(copy\(\${\$\w+},\${\$\w+}\)\){\1"[\w\\\\\s]+";\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+;}}\4[\w\\\\\s]+":(?:\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;)+\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\'\\\\\w\s=>]+;\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\1["\\\\\w\s\'=>\/;]+\3if\(rename\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\3\$\w+=["\w\\\\]+;\1"[\w\\\\\s]+"\.\${\$\w+}[."\\\\\w>;]+}}\4[\w\\\\\s]+":\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;\${\$\w+}=[\$_\w\["\]\\\\]+;\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1["\\\\\w\s\'.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\.["\\\\\w=.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\.["\\\\\w\s>]+;(?:\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;)+\1["\\\\\w\s=\'<\/;]+\3if\(rename\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+;}}\4[\w\\\\\s]+":\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;if\(rmdir\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\3\$\w+=["\\\\\w]+;\1"[\w\\\\\s]+"\.\${\$\w+}[."\\\\\w]+;}\4[\w\\\\\s]+":\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;)+\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";system\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);}\4[\w\\\\\s]+":\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;\2\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\$\w+=["\w\\\\]+;(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;)+\3\$\w+=["\w\\\\]+;if\(\${\$\w+}=fopen\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},"\w"\)\){\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;\3\$\w+=["\w\\\\]+;\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;}\$\w+=["\w\\\\]+;fclose\(\${\$\w+}\);}\4[\w\\\\\s]+":\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=[\$_\w\["\\\\\]]+;\${\$\w+}=basename\([\$_\w\["\\\\\]]+\);\2\${\$\w+}\)\){\1["<\\\\\w\s=\'.]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\.["&\w\\\\\s=\/\-\'>]+;(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;)+\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";if\(move_uploaded_file\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]},\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;unlink\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);\3\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+;}}\4[\w\\\\\s]+":\${\$\w+}=[\$_\w\["\]\\\\]+;\2\${\$\w+}\)\){(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;)+\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;\3\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\$\w+=["\\\\\w]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=explode\(":",\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);if\(\(!is_numeric\(\${\$\w+}\[\d\]\)\)or\(!is_numeric\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\[\d\]\)\)\){\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;\3(?:\$\w+=["\w\\\\]+;)+\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\$\w+=["\w\\\\]+;(?:\${\$\w+}=\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\[\d\];)+\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;while\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}<=\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\){\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\$\w+=["\\\\\w]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=\d;\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=fsockopen\(\$\w+,\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)or\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=\d;if\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}==\d\){\$\w+=["\\\\\w]+;echo\${\$\w+}\.["\\\\\w>]+;}\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\+\+;fclose\(\${\$\w+}\);}}}break;}clearstatcache\(\);(?:\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;){2}\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=scandir\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\);foreach\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\s\w+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\){if\(is_file\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\){(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";)+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=round\(filesize\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\/\d+,\d\);\$\w+=["\w\\\\]+;\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1["<\\\\\w>.\s=]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\/\w\\\\>;]+\$\w+=["\\\\\w]+;\1["<\\\\\w>.\s=]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w\s<\/>]+;\1["<\\\\\w>.\s=]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w=&]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w\/<>;]+\$\w+=["\\\\\w]+;\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+\${\$\w+}[.">\w\\\\\/<]+;(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;)+\3(?:\$\w+=["\\\\\w]+;){2}\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=scandir\(\${\$\w+}\);(?:\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";){2}\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}=count\(\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}\)\-\d;\1"[\w\\\\\s]+"\.\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."<\w>\\\\=&]+\/\w+>";\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]="[\w\\\\\s]+";\1["<\\\\\w>.\s=]+\${\${"[\w\\\\\s]+"}\["[\w\\\\\s]+"\]}[."\\\\\w\s=<\/]+;(?:\1["\\\\\w\s=.\${}\[\]&\':\/<>]+;){3}}}\1["\\\\\w:\s.\$\[\]>()_\'<\/%]+;~msi',
            'id'   => 'darkShell',
        ],
        [
            'full' => '~(\$\w+)=\'([\w\(;\$\)=\s\[\/\]."*]+)\';(\$\w+)=(?:\1\[[-+\(\d*\/\)]+\]\.?)+;(\$\w+)=(?:\1\[[-+\(\d*\/\)]+\]\.?)+;(\$\w+)=(?:\1\[[-+\(\d*\/\)]+\]\.?)+;(\$\w+)=\s+"([\'\w\/+=]+)";(\$\w+)\.=\4;\8\.=\6;\8\.=\5;@(\$\w+)=\3\(\(\'+\),\s+\(\8\)\);@\9\(\);~msi',
            'id'   => 'wso',
        ],
        [
            'full' => '~(?:(?:@?error_reporting|@?set_time_limit)\(\d+\);\s*){1,2}function\s*\w+\((\$\w{1,50})\)\s*{\s*(\$\w{1,50})\s*=\s*strlen\s*\(trim\(\1\)\);\s*(\$\w{1,50})\s*=\s*\'\';\s*(?|for\s*\((\$\w{1,50})\s*=\s*0;\s*\4\s*<\s*\2;\s*\4\s*\+=\s*2\)|(\$\w+)\s*=\s*0;\s*while\s*\(+\4\s*<\s*\2\)+)\s*{\s*\3\s*\.=\s*pack\s*\("C",\s*hexdec\s*\(substr\s*\(\1,\s*\4,\s*2\)\)\);\s*(?:\4\s*\+=\s*2;)?\s*}\s*return\s*\3;\s*}\s*(?:header\("\w+-(?:\w+:)?\s\w+\/\w+;\s*charset=(\w+)"\);\s*)?(\$\w{1,50})\s*=\s*(?:(?:\w+\("(\w+)"\)|\$\w{1,50})\s*\.?\s*)+\s*\.\s*\'([\w\/\+=\\\\]+\'\)\)\);)\';\s*(\$\w{1,50})\s*=\s*create_function\(\'\',\s*\6\);\s*\9\(\);~msi',
            'id'   => 'anonymousFox',
        ],
        [
            'full' => '~(\$my_sucuri_encoding)\s{0,10}=\s{0,10}[\'"]([^\'"]+)[\'"];\s{0,10}(\$tempb64)\s{0,10}=\s{0,10}base64_decode\(\s{0,10}\1\);\s{0,10}eval\(\s{0,10}\3\s{0,10}\);~msi',
            'id'   => 'wsoEval',
        ],
        [
            'full' => '~(?:(?:(\$\w+)\s*\.?=\s*["\'][assert]+["\'];)+\s*(if\s*\(\!\@\$\w+\)\s*\{\$\w+=1;)?\s*@?\1)(\((?:\w+\()+\'[^;]+;\'\)+;(?(2)}))~msi',
            'id'   => 'assertStr',
        ],
        [
            'full' => '~(function\s\w+\(\$\w+,\$\w+,\$\w+\){return\sstr_replace\(\$\w+,\$\w+,\$\w+\);}\s?){3}(\$\w+)\s=\s\'(\w+)\';\s\2\s=\s(\w+)\(\'(\w+)\',\'\',\2\);\s(\$\w+)\s=\s\'(\w+)\';\s\6\s=\s\4\(\'(\w+)\',\'\',\6\);\s(\$\w+)\s=\s\'(\w+)\';\s\9\s=\s\4\(\'(\w+)\',\'\',\9\);\s(\$\w+)\s=\s\'(\$\w+)\';\s(\$\w+)\s=\s\6\(\12,\9\.\'\(\'\.\2\.\'\(\'\.\12\.\'\)\);\'\);\s\14\(\'(\w+)\'\);~msi',
            'id'   => 'funcVar',
        ],
        [
            'full' => '~(\$\w+)=[\'"]([\w</,\s()\$\+}\\\\\'"?\[\]{;%=^&-]+)[\'"];(\$\w+=(?:\s?\1\[\d+\](?:\s?\.?))+;)+((?:\$\w+\(\d+\);)?(\$\w+=(\$\w+)\(["\']{2},(\$\w+\(\$\w+\(["\'][=\w\+\/]+[\'"]\)\))\);\$\w+\(\);|.*?if\s?\(isset\(\${(?:\$\w+\[\d+\]\.?)+}.*?function\s\w+.*?include\s\${(?:\$\w+\[\d+\]\.?)+}\[(?:\$\w+\[\d+\]\.?)+\];\s?}))~msi',
            'id'   => 'dictionaryVars',
        ],
        [
            'full' => '~(?:(?<concatVar>\$\w+)\s?=\s?""\s?;((?:\s?(?P=concatVar)\s?\.=\s?"[\w]+"\s?;\s?)+))?(\$\w+)\s?=\s?(?:(?P=concatVar)|"(?<strVal>[\w]+)")\s?;\s?if\s?\(\s?!function_exists\s?\(\s?"(\w+)"\)\){\s?function\s\5\(\s?(\$\w+)\){\s?(?:\$\w+\s?=\s?""\s?;)?\s?(\$\w+)\s?=\s?strlen\s?\(\s?\6\s?\)\s?\/\s?2\s?;\s?for\s?\(\s?(\$\w+)\s?=0\s?;\s?\8\s?<\s?\7\s?;\s?\8\+\+\s?\)\s?{\s?\$\w+\s?\.=\s?chr\s?\(\s?base_convert\s?\(\s?substr\s?\(\s?\6\s?,\s?\8\s?\*\s?2\s?,\s?2\s?\)\s?,\s?16\s?,\s?10\s?\)\s?\)\s?;\s?}\s?return\s?\$\w+;\s?}\s?}\s?\$\w+\s?=\s?create_function\s?\(\s?null\s?,\s?\5\(\s?\3\)\)\s?;\s?\3\(\)\s?;~msi',
            'id'   => 'concatVarFunc',
        ],
        [
            'full' => '~function\s?(\w+)\(\){(((\$\w+)\.?="\w+";)+)return\seval\(\4\(\w+\(\)\)\);}function\s(\w+)\((\$\w+)\){((?:(\$\w+)\.?="\w+";)+)return\s\8\(\6\);}function\s?(\w+)\(\){((\$\w+)\.?="([\w\/+=]+)";)return\s(\w+)\(\11\);}function\s\13\((\$\w+)\){(\$\w+)=(\w+)\((\w+)\((\w+)\(\14\)\)\);return\s\15;}function\s\17\(\14\){(((\$\w+)\.?="\w+";)+)return\s\21\(\14\);}\1\(\);function\s\16\(\14\){(((\$\w+)\.?="\w+";)+)return\s\24\(\14\);}~msi',
            'id'   => 'concatVarFuncFunc',
        ],
        [
            'full' => '~(?:(?:\s?\$\w+\s?=\s?strrev\([\'"][^\'"]+[\'"]\);\s?)|(?:\s?\$\w+\s?=\s?strrev\([\'"][^\'"]+[\'"]\);\s?)|(?:\s?eval\((?:\$\w+)?\([\'"][^\'"]+[\'"]\)\);\s?)|(?:\s?eval\(\$\w+\(\$\w+\([\'"][^\'"]+[\'"]\)\)\);\s?)){3,4}~msi',
            'id'   => 'evalVarDoubled',
        ],
        [
            'full' => '~(\$\w+)\s?=\s?(\w+)\("([\w+\/=]+)"\);\s?echo\s?\1;~msi',
            'id'   => 'varFuncsEcho',
        ],
        [
            'full' => '~(\$\w+)="";\s*(?:do\s?{[^}]+}\s?while\s?\(\d+>\d+\);\s*\1=\1\."[^"]+";)?.*?\s?.*?(\$\w+)=(\'[^\']+\'\s?\.\s?(?:\'[^\']+\'\s?\.?\s?)+);\s?.*?(?:\s(\$\w+)=((?:\4\[?{?\d+\]?}?\.?)+);\s?|\$\w{1,50}->\w{1,50}\(\);)?\s*(?:function\s\w+\(\){(?:.*?);\s}\s?\1=\w+\(\1,"\w+"\);\s?|\$\w+=array\((?:\'\w+\',?)+\);\s?|\1=\w+\(\1,\sjoin\(\'\',\s\$\w+\)\s?\);\s?|\s?\$\w+\+=\d+;\s?|\1=\w+\(\1,\w+\(\)\);\s?|function\s\w+\(\){\s?|do{\s?if\s?\(\d+<\d+\)\s?{\s?)*.*?(?:\$\w+\s?=\s?\$\w+\([\'"]{2},\s?\$\w+\(\$\w+(?:\(\1\),\s?(?:\$\w+\[\'\w+\'\]\)\s?)?|\)\s?)\);\s?\$\w+\(\);)(?:\s?function\s\w+\((?:\$\w+,\s?\$\w+)?\)(?:.*?);\s}|\s?class\s\w+\s?{(?:.*?);(?:\s}){1,2})+~msi',
            'fast' => '~function\s+\w+\(\)\{\s*global\s*(\$\w+);\s*return\s*(\1[\[{]\d+[\]}]\.?){15};\s*}~msi',
            'id'   => 'varFuncsMany',
        ],
        [
            'full' => '~((\$(?:GLOBALS|{"[\\\\\w]+"})\[[\'"]\w+["\']\])\s?=\s?[\'"]+([\\\\\w]+)["\'];)\s?(?:(\$GLOBALS\[?(\s?(?:\2|\$GLOBALS\[\'\w+\'\])\[\d+\]\.?)+\])\s?=\s?\g<5>+;\s?)+(?:\g<4>\s?=\s[\$_\w]+;\s)+(?:@\g<4>\(\g<5>+\s?,\s?\w+\s?\);\s?)+@\g<4>\(\d+\);\s{0,50}(?:if\s?\(!\g<4>\s?\(\g<5>+\)\)\s{\s{0,50}\g<4>\(\g<5>+,\s\g<5>*\d*\);\s{0,50}}?\s{0,50})*(?:\$\w+\s?=\s?\w+;\s?)*\g<4>\s?=\s\g<5>+;\s?global\s?\$\w+;\s?function\s\w+\(\$\w+,\s\$\w+\)\s{\s?\$\w+\s?=\s?["\']{2};\s?for\s?\(\$\w+\s?=\d+;\s?\$\w+\s?<\s?\g<4>\(\$\w+\)\s?;\s?\)\s?{\s?for\s?\(\s?\$\w+=\d+;\s?\$\w+\s?<\s?\g<4>\(\$\w+\)\s?&&\s?\$\w+\s?<\g<4>\(\$\w+\);\s?\$\w+\+{2},\s?\$\w+\+{2}\)\s?{\s?\$\w+\s?\.=\s?\g<4>\(\g<4>\(\$\w+\[\$\w+\]\)\s?\^\s?\g<4>\(\$\w+\[\$\w+\]\)\);\s?}\s?}\s?return\s\$\w+;\s?}\s?function\s?\w+\(\$\w+,\s?\$\w+\)\s?{\s?global\s?\$\w+;\s?return\s\g<4>\(\g<4>\(\$\w+,\s?\$\w+\),\s?\$\w+\)\s?;\s?}\s?foreach\s?\(\g<4>\sas\s\$\w+=>\$\w+\)\s?{\s?\$\w+\s?=\s?\$\w+;\s?\$\w+\s?=\s?\$\w+;\s?}\s?if\s?\(!\$\w+\)\s?{\s?foreach\s?\(\g<4>\sas\s\$\w+\s?=>\s?\$\w+\)\s?{\s?\$\w+\s?=\s?\$\w+;\s?\$\w+\s?=\s?\$\w+;\s?}\s?}\s?\$\w+\s?=\s?@\g<4>\(\g<4>\(@?\g<4>\(\$\w+\),\s?\$\w+\)\);\s?if\s?\(isset\(\$\w+\[\g<5>+\]\)\s?&&\s?\$\w+==\$\w+\[\g<5>+\]\)\s?{\s?if\s?\(\$\w+\[\g<5>\]\s?==\s?\g<5>\)\s?{\s?\$\w+\s?=\s?array\(\s?\g<5>+\s?=>\s?@\g<4>\(\),\s?\g<5>+\s?=>\s?\g<5>+,\s?\);\s?echo\s?@\g<4>\(\$\w+\);\s?}\s?elseif\s?\(\$\w+\[\g<5>\]\s?==\s?\g<5>\)\s?{\s?eval\(\$\w+\[\g<5>\]\);\s?}\s?(?:exit\(\);)?\s?}\s?}?~msi',
            'id'   => 'globalArrayEval',
        ],
        [
            'full' => '~<\?php\s{0,30}(\$\w+)\s{0,30}=\s{0,30}"(.+?)";\s{0,30}((?:\$\w+\s{0,30}=\s{0,30}(?:\1\[\'\w\s{0,30}\'\s{0,30}\+\s{0,30}\d+\s{0,30}\+\s{0,30}\'\s{0,30}\w\'\]\s{0,30}\.?\s{0,30})+;\s{0,30})+)(\$\w+)\s{0,30}=\s{0,30}"(\d+)";\s{0,30}(?:\$\w+\s{0,30}=\s{0,30}\$\w+\(\s{0,30}\$\w+\s{0,30},\s{0,30}\$\w+\(\s{0,30}"\s{0,30}"\)\s{0,30},\s{0,30}"[\w\+]+"\)\s{0,30};\s{0,30})+(?:\$\w+\s{0,30}=\s{0,30}\$\w+\(\s{0,30}\$\w+\(\s{0,30}\$\w+\)\s{0,30},\s{0,30}\$\w+\(\s{0,30}?\$\w+\)\s{0,30}\)\s{0,30};\s{0,30})+\$\w+\((?:\s{0,30}\$\w+\(\s{0,30}"\s{0,20}\w\s{0,20}"\)\s{0,30}\.?\s{0,30})+"\(\\\\"\w+\\\\"\s{0,30},\s{0,30}"\s{0,30}\.\s{0,30}\$\w+\(\s{0,30}\$\w+\(\s{0,30}"\d+"\s{0,30},\s{0,30}\$\w+\(\s{0,30}"\s{0,20}"\)\s{0,30},\s{0,30}"[\d\w=]+"\)\s{0,30}\)\s{0,30}\.\s{0,30}"\s{0,30}\)\s{0,30};"\)\s{0,30};\s{0,30}\$\w+\s{0,30}=\s{0,30}\$\w+\(\w+\)\s{0,30};\s{0,30}\$\w+\(\s{0,30}(?:\$\w+\(\s{0,30}"\s{0,30}[?>]\s{0,30}"\)\s{0,30}\.\s{0,30})+(\$\w+)\(\s{0,30}(\$\w+)\(\s{0,30}(\$\w+),\s{0,30}(\$\w+)\(\s{0,30}"\s{0,30}"\)\s{0,30},\s{0,30}(\$\w+)\(\s{0,30}"([()\w@|*#\[\]&\/\+=]+)"\s{0,30},\s{0,30}(\$\w+),\s{0,30}(\$\w+)\)\s{0,30}\)\)\s{0,30}\)\s{0,30};\s{0,30}\$\w+\s?=\s?\d+\s?;\s{0,30}\?>~msi',
            'id'   => 'tinkleShell',
        ],
        [
            'full' => '~(?:\$\w+="\w+";)+(\$\w+)="([\w_)(;\/\.*]+)";\$\w+="\w+";function\s(\w+)\((?:\$\w+,?){3}\){return\s?""(?:\.\$\w+\.""){3};}(?:\$\w+=(?:(?:"\w+")|(?:\3\((?:\1\[\d+\],?\.?)+\))|(?:(?:\3\()+(?:\$\w+\,?(?:\)\,)?)+)(?:(?:(?:\3\()+)*(?:(?:\$\w+,?)+)*(?:\),)*(?:\)*))+);)+\$\w+=\3\((?:\1\[\d+\]\.?)+(?:,"")+\);(?:\$\w+=\3\(\3\(\$\w+,\$\w+,\$\w+\),\3\((?:\$\w+,?)+\),\3\(\$\w+,\3\(\$\w+,\$\w+,""\),\$\w+\)\)\."\'(?<str>[\w\/\+]+)\'")\.\3\((?:\1\[\d+\],?\.?)+\);\$\w+\(\$\w+,array\("","}"\.\$\w+\."\/+"\)\);~msi',
            'id'   => 'wsoFunc',
        ],
        [
            'full' => '~\$\w+\[\'\w+\'\]\s?=\s?"[\w;\/\.*)(]+";\s?\$\w+\[\'\w+\'\]\s?=\s?(?:\$\w+\[\'\w+\'\]\[\d+\]\.?)+;\s?\$\w+\s?=\s?(?:"[\w()]*"\.chr\([\d-]+\)\.?)+"\(";\s?\$\w+\s?=\s?"[)\\\\\w;]+";\s?\$\w+\s?=\s?\$\w+\."\'(?<str>[\w\/\+]+)\'"\.\$\w+;\s?\$\w+\[\'\w+\'\]\((?:\$\w+\[\'\w+\'\]\[\d+\]\.?)+,\s?\$\w+\s?,"\d+"\);~msi',
            'id'   => 'wsoFunc',
        ],
        [
            'full' => '~function\s(\w+)\((\$\w+)\)\s{0,50}{\s{0,50}\2=gzinflate\(base64_decode\(\2\)\);\s{0,50}for\((\$\w+)=\d+;\3<strlen\(\2\);\3\+\+\)\s{0,50}{\s{0,50}\2\[\3\]\s?=\s?chr\(ord\(\2\[\3\]\)-(\d+)\);\s{0,50}}\s{0,50}return\s?\2;\s{0,50}}\s{0,50}eval\(\1\([\'"]([\w\+\/=]+)[\'"]\)\);~msi',
            'id'   => 'evalWanFunc',
        ],
        [
            'full' => '~(?:(?:if\s?\(file_exists\("\w+"\)\)\s?{\s?}\s?else\s?{\s?)?\$\w+\s?=\s?fopen\([\'"][^\'"]+\.php[\'"],\s?[\'"]w[\'"]\);)?\s?(\$\w+)\s?=\s?(?:base64_decode\()?[\'"]([^\'"]+)[\'"]\)?;\s?(?:\$\w{1,50}\s?=\s?fopen\([\'"][^\'"]+[\'"],\s?[\'"]\w[\'"]\);\s?)?(?:echo\s?)?fwrite\(\$\w{1,50}\s?,(?:base64_decode\()?\$\w{1,50}\)?\);\s?fclose\(\$\w{1,50}\);\s?}?~msi',
            'id'   => 'funcFile',
        ],
        [
                'full' => '~(\$(?:GLOBALS\[\')?\w+(?:\'\])?\s{0,100}=\s{0,100}array\(\s{0,100}(?:\s{0,100}\'[^\']+\'\s{0,100}=>\s{0,100}\'?[^\']+\'?,\s{0,100})+\s{0,100}\);\s{0,100}((?:\$\w+=(?:[\'"][^\'"]*[\'"]\.?)+;)+)?(?:if\(!\$?\w+\((?:\'\w*\'\.?|\$\w+)+\)\){function\s{0,100}\w+\(\$\w+\){.*?else{function\s{0,100}\w+\(\$\w+\){.*?return\s{0,100}\$\w+\(\$\w+\);\s?}}){2})\$\w+=(?:\'\w*\'\.?)+;\s?(\$\w+)\s{0,100}=\s{0,100}@?\$\w+\(\'\$\w+\',(?:\$\w+\.\'\(.\.\$\w+\.(?:\'[\w(\$);]*\'\.?)+\)|(?:\'[^\']+\'\.?)+\));.*?\3\([\'"]([^"\']+)[\'"]\);~msi',
            'id'   => 'gulf',
        ],
        [
            'full' => '~(\$\w+)=(\w+);\$\w+="(.+?)";(?:\$\w+=\$\w+;)?(\$\w+)=strlen\(\$\w+\);(\$\w+)=[\'"]{2};for\((\$\w+)=\d+;\6<\4;\6\+\+\)\s?\5\s?\.=\s?chr\(ord\(\$\w+\[\6\]\)\s?\^\s?\1\);eval\("\?>"\.\5\."<\?"\);~msi',
            'id'   => 'evalConcatAsciiChars',
        ],
        [
            'full' => '~(?:\$\w+="[\w=]+";\s?)+(\$\w+)\s?=\s?str_replace\((?:"\w*",?)+\);\s?(\$\w+)\s?=\s?\1\((?:"\w*",?\s?)+\);\s?(\$\w+)\s?=\s?\1\((?:"\w*",?)+\);\s?(\$\w+)\s?=\s?\3\("",\s?(\2\(\2\((\1\("([#;*,\.]+)",\s?"",\s?((?:\$\w+\.?)+)\))\)\))\);\s?\4\(\);~msi',
            'id'   => 'evalPost',
        ],
        [
            'full' => '~\$\w+\s?=\s?"e\/\*\.\/";\spreg_replace\(strrev\(\$\w+\),"([\\\\\w]+)\'([\w\/\+=]+)\'([\\\\\w]+)","\."\);~msi',
            'id'   => 'evalPregStr',
        ],
        [
            'full' => '~\$GLOBALS\[\'\w+\'\]=array\(\'preg_re\'\s?\.\'place\'\);\s?function\s\w+\(\$\w+\)\s?{\$\w+=array\("\/\.\*\/e","([\\\\\w]+)\'([\w\/\+]+)\'([\\\\\w]+)","{2}\);\s?return\s\$\w+\[\$\w+\];}\s?\$GLOBALS\[\'\w+\'\]\[\d+\]\(\w+\(\d+\),\w+\(\d+\),\w+\(\d+\)\);~msi',
            'id'   => 'evalPregStr',
        ],
        [
            'full' => '~class\s?\w+{\s?function\s?__destruct\(\){\s?\$this->\w+\(\'([\w&]+)\'\^"([\\\\\w]+)",array\(\(\'([#\w]+)\'\^"([\\\\\w]+)"\)\."\(base64_decode\(\'([\w\+\/=]+)\'\)\);"\)\);\s?}\s?function\s?\w+\(\$\w+,\$\w+\){\s?@array_map\(\$\w+,\$\w+\);\s?}\s?}\s?\$\w+\s?=\s?new\s?\w+\(\);~msi',
            'id'   => 'classDestructFunc',
        ],
        [
            'full' => '~\$\w+="([\\\\\w]+)";\s?\$\w+=\$\w+\(\'([\w\+\/=]+)\'\);\s?\$\w+\s?=\s?"([\\\\\w]+)";\s?\$\w+\s?=\s?\$\w+\([\'"]{2}.\s?eval\(\$\w+\)\);\s?\$\w+\([\'"]{2}\);~msi',
            'id'   => 'createFuncEval',
        ],
        [
            'full' => '~((\$\w+)="([\w-]+)";\s*(?:\$\w+=\'\d+\';\s*)*\s*((?:\$\w+=(?:\2{\d+}\.?)+;)+)+)(?:header[^\)]+\);)?(?:\$\w+=)?(\$\{"[GLOBALSx0-9a-f\\\\]+"})(.+?((.+?\5).+?)+)"[^"]+"\]\(\);~msi',
            'id'   => 'dictionaryCreateFuncs',
        ],
        [
            'full' => '~(\$\w+)\s?=\s?"([\w\s=]+)";\s?(\$\w+)\s?=\s?array\(((?:\d+,?\s?)+)\);\s?(\$\w+)\s?=\s?array\(((?:"[\w\d\s\/\.]+",?\s?)+)\);\s?(\$\w+)\s?=\s?\'\';\s?(?:\$\w+\s=(?:\s?\5\[\d+\]\s?\.?)+;\s?)+(\$\w+)\s?=\s?\$\w+\("\\\\r\\\\n",\s?\1\);\s?for\((\$\w+)=0;\9\s?<\s?sizeof\(\8\);\9\+\+\){\s?\7\s\.=\s?\$\w+\(\8\[\9\]\);\s?}\s?\1\s?=\s?\7;\s?(\$\w+)\s?=\s?\3;\s?(\$\w+)\s?=\s?"";\s?for\((\$\w+)=0;\s?\12<sizeof\(\10\);\s?\12\+=2\){\s?if\(\12\s?%\s?4\){\s?\11\.=\s?substr\(\1,\10\[\12\],\10\[\12\+1\]\);\s?}else{\s?\11\.=strrev\(substr\(\1,\10\[\12\],\10\[\12\+1\]\)\);\s?}\s?};\s?\1\s?=\s?\$\w+\(\11\);\s(\$\w+)\s?=\s?array\(\);\s?(\$\w+)\s?=\s?(?:\5\[\d+\]\s?\.?\s?;?)+;\s?(\$\w+)\s?=\s?(?:\5\[\d+\]\s?\.?\s?)+;\s?(\$\w+)\s?=\s?\'\';\s?for\((\$\w+)=0;\s?\17<strlen\(\1\);\s?\17\+=32\){\s?\13\[\]\s?=\s?substr\(\1,\s?\17,\s?32\);\s?}\s?(?:\$\w+\s?=\s?(?:\5\[\d+\]\s?\.?\s?)+;\s)+\$\w+\s?=\s?\'\';\s?\$\w+\s?=\s?\(\$\w+\(\$\w+\(\$\w+\)\)\)\s?%\s?sizeof\(\$\w+\);\s?\$\w+\s?=\s?\$\w+\[\$\w+\];\s?(\$\w+)\s?=\s?(?:\5\[\d+\]\s?\.?\s?)+;(\s?\18\s?=\s?\$_POST\[\18\];\s?(\14\s?=\s?\15\(\$_COOKIE\[\14\]\);)\s?\$\w+\s?=\s?\5\[\d+\]\s?\.\s?\5\[\d+\];\s?(eval\(\$\w+\(\18\)\);)\s?if\(!\16\){\s?((?:\$\w+\s?=\s?(?:\5\[\d+\]\s?\.?\s?)+;\s)+)(\$\w+\(\$\w+\);\s?echo\(\$\w+\);)\s?})~msi',
            'fast' => '~(\s?(\$\w+)\s?=\s?\$_POST\[\2\];\s?((\$\w+)\s?=\s?\$\w+\(\$_COOKIE\[\4\]\);)\s?(\$\w+)\s?=\s?(\$\w+)\[\d+\]\s?\.\s?\6\[\d+\];\s?(eval\(\$\w+\(\2\)\);)\s?if\(!\5\){\s?((?:\$\w+\s?=\s?(?:\6\[\d+\]\s?\.?\s?)+;\s)+)(\$\w+\(\$\w+\);\s?echo\(\$\w+\);)\s?})~msi',
            'id'   => 'evalPostDictionary',
        ],
        [
            'full' => '~(\$\w)\s?=\s?str_rot13\("([^"]+)"\);preg_replace\("//e","\1",""\);~msi',
            'id'   => 'strrotPregReplaceEval',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*[^\']+\'([^\']+)\';\s*(\$\w+)\s*=\s*\'([^\']+)\';\s*if\(!file_exists\(\$file\)+\{\s*@file_put_contents\(\1,base64_decode\(base64_decode\(\3\)+;\s*\}\s*\@include\s*\$file;~msi',
            'id'   => 'dropInclude',
        ],
        [
            'full' => '~(?(DEFINE)(?\'c\'(?:/\*[^/]*/?\*/)*))(?&c)@?(eval|echo|(\$\w+)\s*=\s*create_function)(?:\/\*+\/)?\s*(?&c)\((?&c)(\'\',)?\s*([\'"?>.\s]+)?\s*\(?\s*@?\s*((?&c)base64_decode(?&c)\s*\((?&c)|(?&c)pack(?&c)\s*\(\'H\*\',|(?&c)convert_uudecode(?&c)\s*\(|(?&c)htmlspecialchars_decode(?&c)\s*\(|(?&c)stripslashes(?&c)\s*\(|(?&c)gzinflate(?&c)\s*\(|(?&c)strrev(?&c)\s*\(|(?&c)str_rot13(?&c)\s*\(|(?&c)gzuncompress(?&c)\s*\(|(?&c)urldecode(?&c)\s*\(|(?&c)rawurldecode(?&c)\s*\(|(?&c)eval(?&c)\s*\()+.*?[^\'")]+(?&c)(((?&c)\s*(?&c)\.?(?&c)[\'"]((?&c)[^\'";]+(?&c)[\'"](?&c)*\s*)+(?&c))?(?&c)\s*[\'"\);]+(?&c))+(?&c)(\s*\2\(\);(?&c))?~msi',
            'id'   => 'evalComments',
        ],
        [
            'full' => '~\@?error_reporting\(0\);\@?set_time_limit\(0\);(?:\s*rename\([^;]+;)?\s*(\$\w+)="([^"]+)";\s*\1=\@?urldecode\(\1\);\1=\@?strrev\(\1\);\@?eval\(\1\);~msi',
            'id'   => 'strrevUrldecodeEval',
        ],
        [
            'full' => '~(\$\w+\s*=\s*"\w+";\s*\@?error_reporting\(E_ERROR\);\s*\@?ini_set\(\'display_errors\',\'Off\'\);\s*\@?ini_set\(\'max_execution_time\',\d+\);\s*header\("[^"]+"\);\s*)?(\$\w+)\s*=\s*"([^"]+)";\s*(\$\w+)\s*=\s*pack\("H\*",str_rot13\(\2\)+;\s*(?:eval\(\4\);|(\$\w+)=\$\w+\(\'\',\4\);\s*\5\(\);)~msi',
            'id'   => 'evalPackStrrot',
        ],
        [
            'full' => '~\$\w+\s*=\s*\d+;\s*function\s*(\w+)\(\$\w+,\s*\$\w+\)\{\$\w+\s*=\s*\'\';\s*for[^{]+\{([^}]+\}){2}\s*\$\w{1,40}\s*=\s*((\'[^\']+\'\s*\.?\s*)+);\s*\$\w+\s*=\s*Array\(((\'\w\'=>\'\w\',?\s*)+)\);\s*eval(?:/\*[^/]\*/)*\(\1\(\$\w+,\s*\$\w+\)+;~msi',
            'id'   => 'urlDecodeTable',
        ],
        [
            'full' => '~((?:\$\w+=\'\w\';)+)((?:\$\w+=(\$\w+\.?)+;)+)eval\((\$\w+\()+\'([^\']+)\'\)+;~msi',
            'id'   => 'evalVarChar',
        ],
        [
            'full' => '~(\$\w+\s*=\s*(base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|htmlspecialchars_decode\s*\()+"([^"]+)"\);)\s*eval\("?(\$\w+)"?\);~msi',
            'id'   => 'evalVarFunc',
        ],
        [
            'full' => '~((?:\$\w+\s*=\s*("[\w=+/\\\\]+");\s*)+)(eval\((\$\w+\(+)+(\$\w+)\)+);~msi',
            'id'   => 'evalVarsFuncs',
        ],
        [
            'full' => '~<\?php\s*(?:/\*[^=\$\{\}/]{10,499}[^\*\$\(;\}\{=]{1,99}\*/\s*)?(\$[^\w=(,${)}]{0,50})=\'(\w{0,50})\';((?:\$[^\w=(,${)}]{0,50}=(?:\1{\d+}\.?){0,50};){1,20})(\$[^=]{0,50}=\$[^\w=(,${)}]{1,50}\(\$[^\w=(,${)}]{1,50}\(\'\\\\{2}\',\'/\',__FILE__\)\);(?:\$[^\w=(,${)}]{0,50}=\$[^\w=(,${)}]{0,50}\(\$[^\w=(,${)}]{0,50}\);){2}\$[^\w=(,${)}]{0,50}=\$[^\w=(,${)}]{0,50}\(\'\',\$[^\w=(,${)}]{0,50}\)\.\$[^\(]{0,50}\(\$[^\w=(,${)}]{0,50},\d+,\$[^\w=(,${)}]{0,50}\(\$[^\w=(,${)}]{0,50},\'@ev\'\)\);\$[^\w=(,${)}]{0,50}=\$[^\(]{0,50}\(\$[^\w=(,${)}]{0,50}\);\$[^\w=(,${)}]{0,50}=\$[^\w=(,${)}=]{0,50}=\$[^\w=(,${)}]{0,50}=NULL;@eval\(\$[^\w=(,${)}]{0,50}\(\$[^\w=(,${)}(]{0,50}\(\$[^\w=(,${)}]{0,50},\'\',\$[^\w=(,${)}]{0,50}\(\'([^\']{0,500})\',\'([^\']{0,500})\',\'([^\']{0,500})\'\){4};)unset\((?:\$[^,]{0,50},?){0,20};return;\?>.+~msi',
            'id'   => 'evalFileContent',
        ],
        [
            'full' => '~echo\s{0,50}"(\\\\\${\\\\x\d{2}(?:[^"]+(?:\\\\")*)*[^"]+)";~msi',
            'id'   => 'echoEscapedStr',
        ],
        [
            'full' => '~file_put_contents\(\$\w+\[[\'"]\w+[\'"]\]\.[\'"][/\w]+\.php[\'"],(base64_decode\([\'"]([\w=]+)[\'"]\))\)~msi',
            'id'   => 'filePutDecodedContents',
        ],
        [
            'full' => '~eval\(implode\(array_map\([\'"](\w+)[\'"],str_split\([\'"]([^\'"]+)[\'"]\)\)\)\);~msi',
            'id'   => 'evalImplodedArrStr',
        ],
        [
            'full' => '~(\$\w+)\s?=\s?\'(.*?NULL\);)\';\s*(\$\w+)\s?=\s?[\'"]([\w\\\\]+)[\'"];\s?\3\([\'"]/\(\.\*\)/e[\'"],\s?[\'"]([\w\\\\]+)[\'"],\s?NULL\);~msi',
            'id'   => 'pregReplaceCodeContent',
        ],
        [
            'full' => '~((?:\$\w+\s*\.?=\s*"[^"]*";\s*)+)(\$\w+)\s*=\s*str_replace\(\s*"([^"]+)",\s*"",\s*\$\w+\s*\);\s*(\$\w+)\s*=\s*str_replace\(\s*"([^"]+)",\s*"",\s*"([^"]+)"\s*\);\s*(\$\w+)\s*=\s*\4\(\s*\2\s*\);\s*\7\s*=\s*"[^"]+\7";\s*eval\(\s*\7\s*\);~msi',
            'id'   => 'concatVarsReplaceEval',
        ],
        [
            'full' => '~(\$\w{1,50})\s?=\s?file_get_contents\(__FILE__\);\s?\1\s?=\s?base64_decode\(substr\(\1,\s?([+-]\d+)\)\);\s*\1\s?=\s?gzuncompress\(\1\);\s*eval\(\1\);\s*die\(\);\?>\s*([^"\']+)~msi',
            'fast' => '~\$\w{1,50}\s?=\s?file_get_contents\(__FILE__\);\s?\$\w{1,50}\s?=\s?base64_decode\(substr\(\$\w{1,50},\s?([+-]\d+)\)\);\s*\$\w{1,50}\s?=\s?gzuncompress\(\$\w{1,50}\);\s*eval\(\$\w{1,50}\);\s*die\(\);\?>\s*([^"\']+)~msi',
            'id' => 'decodeFileContent',
        ],
        [
            'full' => '~((\$\w+\s*=\s*\(?(base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|htmlspecialchars_decode\s*\()*((?:"([^"]+)";\s*)|(?:\$\w+)\)*;\s*))+)(eval\("?(\$\w+)"?\);)~msi',
            'id'   => 'evalVarFunc2',
        ],
        [
            'full' => '~((\$\w+)\s*=\s*"([^"]+)";)\s*((\$\w+)\s*=\s*array\(((\s*\d+,?)+)\);)\s*((\$\w+)\s*=\s*array\(((\s*"[^"]+",?)+)\);)\s*(\$\w+)\s*=\s*\'\';(\s*\$\w+\s*=\s*(?:\9\[\d+\]\s*\.?\s*)+;)+(.+?(\s*\$\w+\s*=\s*\w+\((?:\9\[\d+\]\s*\.?\s*)+)\);\s*eval\(\$\w+\);\s*\})~msi',
            'fast' => '~((\s*(\$\w+)\s*=\s*\w+\((\$\w+)\[\d+\]\s*\.\s*(?:\4\[\d+\]\s*\.?\s*)+)\);\s*eval\(\3\);\s*\})~msi',
            'id'   => 'evalArrays',
        ],
        [
            'full' => '~\$\w+\s?=\s?preg_replace\([\'"]/([^\'"/]+)/\w{0,2}[\'"],[\'"]([^\'"]+)[\'"],[\'"]{2}\);~msi',
            'id'   => 'pregReplaceVar',
        ],
        [
            'full' => '~function\s(\w+)\((\$\w+),\s?(\$\w+)\){\s?(\$\w+)=[\'"]{2};\s?for\(\$\w+=0;\$\w+<strlen\(\2\);\)\s?for\(\$\w+=0;\$\w+<strlen\(\3\);\$\w+\+\+,\s?\$\w+\+\+\)\s?\4\s?\.=\s?\2{\$\w+}\s?\^\s?\3{\$\w+};\s?return\s?\4;\s?};eval\(\1\(base64_decode\([\'"]([^\'"]+)[\'"]\),[\'"]([^\'"]+)[\'"]\)\);~msi',
            'id'   => 'evalFuncTwoArgs',
        ],
        [
            'full' => '~function\s(\w+)\(\$\w+\)\s?{\s?\$\w+\s?=\s?[\'"]{2};\s?unset\(\$\w+\);\s?\$\w+\s?=\s?[\'"]([^\'"]+)[\'"];\s?\$\w+\s?=\s?preg_replace\("/([^"]+)/",\s?[\'"]{2},\s?\$\w+\);\s?\$\w+\s?=\s?(?:(?:[\'"]\w+[\'"]|\$\w+)\.?)+;\s?\$\w+\s?=\s?\$\w+\([\'"]\$\w+[\'"],\s?\$\w+\);\s?@?\$\w+\(\$\w+\);\s?}\s?function\s?(\w+)\(\$\w+\)\s?{\s?\$\w+\s?=\s?[\'"](.*?)[\'"];\s?\$\w+\s?=\s?preg_replace\("/([^\'"]+)/",\s?[\'"]{2},\s?\$\w+\);\s?return\s?\$\w+\(\$\w+\);\s?}\s?\1\(\4\(\s?join\([\'"]([^\'"]+)[\'"],\s?array\(((?:[\'"][^\'"]+[\'"][,\s]*)+)\)+;~msi',
            'id'   => 'evalPregReplaceFuncs',
        ],
        [
            'full' => '~error_reporting\(0\);((?:\$\w+=\'[^;]+;)+)error_reporting\(0\);((?:\$\w+=\$\w+\(\$\w+\(\'([^\']+)\'\)\);)+\$\w+=(?:\$\w+\()+\'([^\']+)\'\)+\.(?:\$\w+\()+\'([^\']+)\'\)+;\$\w+=(?:\$\w+\()+\'([^\']+)\'\)+;\$\w+=(?:\$\w+\()+"\\\\n",\s*\'\',\s*\'([^\']+)\'\)+;(?:[^}]+\})+}\s*echo\s*(?:\$\w+\()+\'([^\']+)\'\)+);exit;~msi',
            'id'   => 'urlMd5Passwd',
        ],
        [
            'full' => '~((?:\$\w+\s?=\s?\'(?:[^\']+)\';\s?)+)((?:\$\w+\s?=\s?(?:\$\w+(?:\[[\'"]?\d+[\'"]?\])?\s?\.?\s?)+;)+\$\w+\s?=\s?\$\w+\s?\(\$\w+,(?:\$\w+(?:\[[\'"]?\d+[\'"]?\])?\s?\.?\s?)+\);\s*\$\w+\(\$\w+,(?:\$\w+(?:\[[\'"]?\d+[\'"]?\])?\s?[.,]?\s?)+\);)~msi',
            'fast' => '~((?:\$\w+\s?=\s?(?:\$\w+(?:\[[\'"]?\d+[\'"]?\])?\s?\.?\s?)+;)+\$\w+\s?=\s?\$\w+\s?\(\$\w+,(?:\$\w+(?:\[[\'"]?\d+[\'"]?\])?\s?\.?\s?)+\);\s*\$\w+\(\$\w+,(?:\$\w+(?:\[[\'"]?\d+[\'"]?\])?\s?[.,]?\s?)+\);)~msi',
            'id'   => 'ManyDictionaryVars',
        ],
        [
            'full' => '~function\s(\w+)\(\$\w+\)\s?{\s?\$\w+\s?=\s?(?:[\'"][\\\\\w]+[\'"]\(\d+\s?[-+]\s?\d+\)\s?\.?\s?)+;\s?(?:\$\w+\s?=\s?\$\w+\([\'"](?:edoced_46esab|etalfnizg|ecalper_rts)[\'"]\);\s?)+\$\w+\s?=\s?\$\w+\(array\(((?:\s?"[^"]+",?)+)\),\s?[\'"]{2},\s?\$\w+\);\s?return\s?(?:\$\w+\(){2}\$\w+\)\);\s?}\s?(\$\w+\s?=\s?[\'"]\w+[\'"];)?\s?ob_start\(\);\s?\?>(.*?)<\?php\s?\$\w+\s?=\s?ob_get_clean\(\);\s?eval\(\1\(\$\w+\)\);\s?\?>~msi',
            'id'   => 'evalBuffer',
        ],
        [
            'full' => '~((?:\$\w+\s?=\s?[\'"]\w*[\'"];\s?){0,50}(\$\w+)\s?=\s?[\'"]([^\'"]+)[\'"];(?:\$\w+\s?\.?=\s?(?:\$\w+{\d+}\.?)+;)+)\s?(eval\((\$\w+)\([\'"]([^\'"]+)[\'"]\)\);)~msi',
            'id' => 'evalDictionaryVars',
        ],
        [
            'full' => '~\$\w+\s?=\s?[\'"]([^\'"]+)[\'"];(?:\$\w+\s?=\s?base64_decode\([\'"][^\'"]+[\'"]\);)+\$\w+\s?=\s?\$\w+\(\$\w+\(\$\w+\)\);\$\w+\s?=\s?\$\w+\(\$\w+\);(\$\w+)\s?=\s?[\'"]{2};for\(\$\w+\s?=\s?0\s?;\s?\$\w+\s?<\s?\$\w+\s?;\s?\$\w+\+\+\){\2\s?\.=\s?\$\w+\(\(\$\w+\(\$\w+\[\$\w+\]\)\^(\d+)\)\);}eval\(\2\);return;~msi',
            'id' => 'evalFuncXored',
        ],
        [
            'full' => '~[\'"]-;-[\'"];(.*?\(\'\\\\\\\\\',\'/\',__FILE__\)\);.*?,[\'"];[\'"]\),[\'"]"[\'"]\);.*?)[\'"]-;-[\'"];((\$\w+)=[\'"]([^\'"]+)[\'"];.*?\$\w+\s?\.\s?\3,\s?[\'"]([^\'"]+)[\'"],\s?[\'"]([^\'"]+)[\'"]\)\)\).*?)[\'"]-;-[\'"];(.*?)[\'"]-;-[\'"];~msi',
            'id' => 'evalFuncExplodedContent',
        ],
        [
            'full' => '~(\$\w{0,100}\s?=\s?(?:chr\(\w{1,10}\)\s?\.?\s?){1,100};\s?(?:\$\w{0,100}\s?=\s?(?:\s?(?:[\'"][\\\\\w]{1,10}[\'"]|[\d\.]{1,5}\s[*\+\-\.]\s\d{1,5})\s?\.?)+?;\s?){1,10}(?:\$\w{0,100}\s?=\s?(?:chr\(\w{1,10}\)\s?\.?){1,100};)?\s?\$\w{1,50}\s?=\s?\$\w{1,50}\(\$\w{1,50}\((?:[\'"][^\'"]{1,500}[\'"]\s?\.?\s?)+\),\s?(?:[\'"][^\'"]{1,500}[\'"]\s?\.?\s?)+,\s?substr\(hash\([\'"]SHA256[\'"],(?:\s?[\'"]\d{1,15}[\'"]\s?\.?){2},\s?true\),\s?(\d{1,10}),\s?(\d{1,10})\),\s?OPENSSL_RAW_DATA,\s?\$\w{1,50}\);.*?)(\$\w{1,50})\s?=\s?\$\w{1,50}\([\'"]([^\'"]+)[\'"],\s*[\'"]{2},\s*[\'"]([^\'"]+)[\'"]\);\s?return\s?@eval\(((?:\$\w{1,50}\s?\()+\$\w{1,50}(?:\)\s?)+);\s?exit;~msi',
            'id' => 'evalEncryptedVars',
        ],
        [
            'full' => '~function\s(\w+)\((\$\w+),\s*(\$\w+)[^)]+\)\s*\{\s*\$\w+\s*=\s*\2;\s*\$\w+\s*=\s*\'\';\s*for\s*\(\$\w+\s*=\s*0;\s*\$\w+\s*<\s*strlen\(\$\w+\);\)\s*{\s*for\s*\(\$\w+\s*=\s*0;\s*\$\w+\s*<\s*strlen\(\3\)\s*&&\s*\$\w+\s*<\s*strlen\(\$\w+\);\s*\$\w+\+\+,\s*\$\w+\+\+\)\s*{\s*\$\w+\s*\.=\s*\$\w+\[\$\w+\]\s*\^\s*\3\[\$\w+\];\s*}\s*}\s*return \$\w+;\s*}\s*\$\w+\s*=\s*["\'][^"\']+[\'"];\s*\$\w+\s*=\s*[\'"]([^\'"]+)["\'];\s*(?:\$\w+\s*=\s*["\']+;\s*)+(?:foreach[^{]+{[^}]+}\s*)+(\$\w+)\s*=\s*\$\w+\([create_funion\'. "]+\);\s*(\$\w+)\s*=\s*\5\(["\'][^"\']*[\'"],\s*\$\w+\(\1\(\$\w+\(\$\w+\),\s*["\']([^\'"]+)["\']\)+;\s*\6\(\);~msi',
            'id' => 'xoredKey',
        ],
        [
            'full' => '~(\$\w+)=str_rot13\(\'[^\']+\'\);(\$\w+)=str_rot13\(strrev\(\'[^\']+\'\)\);(\s*eval\(\1\(\2\(\'([^\']+)\'\)+;)+~msi',
            'id' => 'evalGzB64',
        ],
        [
            'full' => '~(function\s*(_\d+)\((\$\w+)\)\s*{(\$\w+)=Array\(\'[^)]+\'\);return\s*base64_decode\(\4\[\3\]\);\})(.+?\2\(\d+\))+[^;]+;exit;~msi',
            'id' => 'evalArrayB64',
        ],
        [
            'full' => '~http_response_code\(\d{1,3}\);function\s?(\w{1,100})\(\$\w{1,50}\){if\s?\(empty\(\$\w{1,50}\)\)\s?return;\$\w{1,50}\s?=\s?"[^"]{1,500}";(?:(?:\$\w{1,50}\s?=\s?[\'"]{0,2}){1,4};){1,2}\$\w{1,50}\s?=\s?0;\$\w{1,50}\s?=\s?"";\$\w{1,50}\s?=\s?preg_replace\("[^"]{1,50}",\s?"",\s?\$\w{1,50}\);do{.*?while\s?\(\$\w{1,50}\s?<\s?strlen\(\$\w{1,50}\)\);return\s?\$\w{1,50};}eval\(\1\(hex2bin\("(\w{1,30000})"\)\)\);~msi',
            'id' => 'evalFuncBinary',
        ],
        [
            'full' => '~(\$\w{1,50}\s?=\s?\'\w{1,500}\';){1,5}\$\w{1,50}\s?=\s?(?:\$\w{1,50}\.?){1,10};\$\w{1,50}=\$\w{1,50}\([\'"]H\*[\'"],[\'"](\w{1,200})[\'"]\);\s?\$\w{1,50}\("[^"]{1,100}","(\\\\x[^\']{1,500})(\'[^\']{1,50000}\')\\\\x[^"]{1,50}",[\'"]{2}\);~msi',
            'id' => 'evalPackFuncs',
        ],
        [
            'full' => '~parse_str\s*\(((?:\s?\'[^\,]+\'\s?\.?\s?){1,500}),\s?(\$\w{1,50})\s?\)\s?;\s?@?((?:eval\s?\()?\s?\2\s?\[\s?\d{1,5}\s?\]\s?\(\s?\2\s?\[\s?\d{1,5}\s?\]\s?(?:,\s?array\s?\(\s?\)\s?,\s?array\s?\(\s?\'([^\']{1,10})\'\s?\.(\$\w{1,50}\s?\[\s?\d\s?\]\s?\(\s?\$\w{1,50}\s?\[\s?\d\s?\]\s?\(\s?\$\w{1,50}\s?\[\s?\d{1,2}\s?\]\s?\()|\(\2\[\s?\d{1,5}\s?\]\s?\())\s?(\'[^\']+\'\s?)(\)\s*)?\)\s*\)\s*\.\s?\'([^\']{1,10})\'\s?\)\s?\)\s?;~msi',
            'id' => 'parseStrFunc',
        ],
        [
            'full' => '~eval\("\\\\(\$\w+)=(gz[^\)]+\)\);)"\);eval\("\?>"\.\1\);~msi',
            'id' => 'evalGzinflate',
        ],
        [
            'full' => '~function\s?(\w{1,50})\(\$\w{1,50}\)\s?{\s?(\$\w{1,50})\s?=\s?\("([^"]{1,500})"\);\s?(?:\$\w{1,50}\s?=\s?(?:"[^"]+"|\$\w{1,50}|[\'"]{2});\s?)+for\(\$\w{1,50}\s?=\s?0;\s?\$\w{1,50}<strlen\(\$\w{1,50}\);\s?\)\s?{\s?for\(\$\w{1,50}\s?=\s?0;\s?\(\$\w{1,50}<strlen\(\2\)\s?&&\s?\$\w{1,50}<strlen\(\$\w{1,50}\)\);\s?\$\w{1,50}\+\+,\$\w{1,50}\+\+\){\s?(?:\$\w{1,50}\s?=\s?"[^"]+";\s?){1,2}\$\w{1,50}\s?\.=\s?\$\w{1,50}{\$\w{1,50}}\s?\^\s?\$\w{1,50}{\$\w{1,50}};\s?\$\w{1,50}\s?=\s?"[^"]+";\s?}\s?}\s?return\s?\$\w{1,50};\s?}\s?(\$\w{1,50})\s?=\s?preg_replace\("([^"]+)",\s?"",\s?"([^"]+)"\);\s?(?:\s?\$\w{1,50}\s?=\s?(?:"[^"]+"|\w{1,50}\(\$\w{1,50}\("[^"]+"\)\)|\$\w{1,50}\(\)\.\s?\w{1,50}\(\$\w{1,50}\("[^"]+"\)\)|"[^"]+"\s*\.\s*\w+\(\$\w+\("[^"]+"\)\));\s?){1,50}(\$\w{1,50}\(\$\w{1,50},(?:\$\w{1,50}\.?)+\);)\s?(?:\$\w{1,50}\s?=\s?"[^"]+";\s?|include\s?\$\w{1,50};\s){1,50}~msi',
            'id' => 'funcVars',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"([^"]+)";(?:\$\w+\s*=\s*(?:\1\[\d+\][\.;])+)+@?(?:\$\w+[\(,])+((?:\1\[\d+\][\.;\)])+)\)\),\$\w+\[\d+\],\$\w+\[\d+\]\);~msi',
            'id' => 'dictVars',
        ],
        [
            'full' => '~\$\w{1,50}\s?=\s?(?:\'\'|\.|chr\(\d+\)|\'\w+\')+\s?;\$\w{1,50}\s?=\s?\$\w{1,50}\(\'\',array\(((?:"[^"]+",?)+)\)\);(?:\$\w{1,50}\s?=\s?(?:\'\'|\.|chr\(\d+\)|\'\w+\')+\s?;)+\$\w{1,50}\s?=\s?\$\w{1,50}\(\'\',\$\w{1,50}\(((?:\'[^\']+\'\s?\.?)+)\)\);\$\w{1,50}\(\);\$\w{1,50}\(\$\w{1,50}\(\$\w{1,50}\)\);~msi',
            'id' => 'decodedDoubleStrSet',
        ],
        [
            'full' => '~(\$\w{1,100})=[\'"]([^"\']+)[\'"];(\$\w{1,100}=(?:(?:strrev\("[^"]+"\)|"[^"]+")\.?)+;(\$\w{1,100})\s?=\s?\$\w{1,100}\([\'"]([^"\']+)[\'"]\);\$\w{1,100}=(?:(?:strrev\("[^"]+"\)|"[^"]+")\.?)+;(\$\w{1,100})\s?=\s?\$\w{1,100}\(\'\1\',\$\w{1,100}\);\$\w{1,100}\(\1\);)~msi',
            'fast' => '~(\$\w{1,100})=[\'"]([^"\']+)[\'"];(\$\w{1,100}=(?:(?:strrev\("[^"]+"\)|"[^"]+")\.?)+;(\$\w{1,100})\s?=\s?\$\w{1,100}\([\'"]([^"\']+)[\'"]\);\$\w{1,100}=(?:(?:strrev\("[^"]+"\)|"[^"]+")\.?)+;(\$\w{1,100})\s?=\s?\$\w{1,100}\(\'\$\w{1,100}\',\$\w{1,100}\);\$\w{1,100}\(\$\w{1,100}\);)~msi',
            'id' => 'createFuncStrrev',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*create_function\(\'\$\w+\',strrev\(\'[^\']+\'\)\);\s*\1\(strrev\(\'([^\']+)\'\)\);~msi',
            'id' => 'strrevBase64',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"([^"]+)";if\(!function_exists\("([^"]+)"\)\){function\s*\3\(\$\w+\)\{\$\w+=(\d+);foreach\(array\(((?:"[0-9a-f]+",?)+)\)as\$\w+=>\$\w+\)[^}]+\}\}\3\(\1\."([^"]+)"\);~msi',
            'id' => 'customDecode',
        ],
        [
            'full' => '~((?:\$\w+\s*=\s*[abcdehnoprstux\._64\'"]+;\s*)+)(\$\w+="?\w+["\(\)]*;\s*)+\$\w+="[^"]+";\s*\$\w+=(\$\w+\("([^"]+)"\);)[^/]+/pre>\';~msi',
            'id' => 'expDoorCode',
        ],
        [
            'full' => '~include\((base64_decode\(\'([^\']+)\'\))\);~msi',
            'id' => 'includeB64',
        ],
        [
            'full' => '~(\$\w+)=strrev\(\'nib2xeh\'\);(\$\w+)=array\(((?:\'[^\']+\',?)+)\);(\$\w+)\s*=\s*\'\';for\s*\(\$\w+\s*=\s*0;\s*\$\w+\s*<\s*\d+;\s*\$\w+\+\+\)\s*\{\4\s*\.=\s*str_replace\(array\(((?:\'([^\']*)\',?)+)\),\s*array\(((?:\'[^\']*\',?)+)\),\s*\2\[\$\w+\]\);\}eval\(\1\(\4\)\);~msi',
            'id' => 'nib2xeh',
        ],
        [
            'full' => '~error_reporting\(0\);\s*\$\w+\s*=\s*"[0-9a-f]{32}";\s*((\$\w+)\s*=\s*((?:\w+\()+)\'([^\']+)\'\)+;\$\w+\s*=\s*"";for\s*\(\$\w+\s*=\s*0;\s*\$\w+\s*<\s*120;\s*\$\w+\+\+\)[^}]+}\$\w+\s*=\s*strlen\(\2\);\$\w+\s*=\s*strlen\(sha1\(hash\(str_rot13\("fun256"\),\s*md5\(\$\w+\)+;for[^}]+}[^}]+}eval\(\$\w+\);)~msi',
            'id' => 'fun256',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*((?:\w+\()+)\'([^\']+)\'\)+;\s*if\s*\(\s*\'\w{40,40}\'\s*==\s*sha1\(\s*\1\s*\)\s*\)\s*{\s*\1\s*=\s*gzinflate\s*\(\s*gzinflate\s*\(\s*base64_decode\(\s*\1\s*\)\s*\)\s*\)\s*;\s*\$\w{1,10}\s*=\s*""\s*;for\s*\([^)]+\)\s*{[^}]+}\s*(?:\s*\$[^;]+;\s*)+for\s*\([^)]+\)\s*{\s*\$[^;]+;\s*if\s*\([^)]+\)\s*{[^}]+}(?:\s*\$[^;]+;\s*)+}\s*eval\s*\(\s*\$\w+\s*\)\s*;\s*}\s*else\s*{[^}]+}~msi',
            'id' => 'fun256',
        ],
        [
            'full' => '~(\$\w+)\s?=\s?\'([^\']+)\';\s?(\$\w+\s?=\s?(?:\1\[\d+\]\.?)+;\s?(?:(?:\$\w+\s?=\s?(?:\$\w+\()+(?:(?:\1\[\d+\])\.?|"[^"]+"\.?)+)\)+;\s?)+)(\$\w+\s?=\s?\$\w+\(\'H\*\',\s?\$\w+\(\'/\[([^]]+)\]\+/\w\',\'\',\s?(\$\w+)\(\1\)\)\);\s?eval\(\$\w+\);)~msi',
            'id' => 'evalPackPreg',
        ],
        [
            'full' => '~((?:\$_\w{1,50}\s?=\s?"[^"]{1,100}";)+)@eval\("\?>"\.(\$_\w{1,50}\((/\*.*?\*\/)\$\w{1,50}\("[^"]+"\)\))\);~msi',
            'id' => 'evalVarWithComment',
        ],
        [
            'full' => '~(?(DEFINE)(?\'s\'((?:chr\([0-9a-fx]+([/\-+\*][0-9a-fx]+)?\)|str_rot13\(\'[^\']+\'\)|base64_decode\(\'[^\']+\'\)|\'[^\']*\')[\.]?)+))(\$\w+)=create_function\(((?P>s)),((?P>s))\);\4\(base64_decode\(((?P>s))\)\);~msi',
            'id' => 'createFuncObf',
        ],
        [
            'full' => '~(\$[\w_]{1,50})\s*=\s*\[\s*base64_decode\s*\(\s*[\'"]([\w=]+)[\'"]\s*\)\s*,\s*([^;]{2,200})\]\s*;\s*(if\s*[^}]+}\s*else\s*{[^}]+}\s*function\s\w+[^}]+})~mis',
            'fast' => '~(\$[\w_]{1,50})\s*=\s*\[\s*base64_decode\s*\(\s*[\'"]([\w=]+)[\'"]\s*\)\s*,\s*([^;]{2,200})\]\s*;\s*(if\s*[^}]+}\s*else\s*{[^}]+}\s*function\s\w+[^}]+})~mis',
            'id' => 'base64Array',
        ],
        [
            'full' => '~(\$[\w]{1,34}\s*=\s*[\'"](?:[\\\\\w]{1,32}\\\[\\\\\w]{1,32})[\'"]\s*;\s*(?:\$[\w]{1,34}\s*=\s*[\'"][^\'"]+[\'"];){1,3})\s*@?eval\s*\(\s*([^;]{0,100})\);~mis',
            'id' => 'simpleVarsAndEval',
        ],
        [
            'full' => '~(if\(defined\(\'PHP_MAJOR_VERSION\'\)[^{]{1,30}{\s*if[^}]+}\s*}\s*.*?if\s*\(\s*!\s*function_exists\s*\(\s*\'nel\'\s*\)\s*\)\s*{\s*)(function\s*nel\s*\(\s*\$i\s*\)\s*{\s*\$[\w]+\s*=\s*array\(([^)]+)\);[^}]+})(.*}\s*exit\s*;\s*}\s*})~mis',
            'id' => 'replaceFuncWithBase64DecodeArray',
        ],
        [
            'full' => '~\$\w{1,50}\s?=\s?(?:\'[^\']+\'\.?)+;\$\w{1,50}\s?=\s?create_function\(\'\$\w{1,50}\',\$\w{1,50}\);((?:\$\w{1,50}\s?=\s?(?:\'[^\']+\'\.?)+;)+)\$\w{1,50}\(((?:\$\w{1,50}\()+"[^"]+"\)+;)~msi',
            'id' => 'createFuncVars',
        ],
        [
            'full' => '~\$\w{1,50}\s?=\s?json_decode\((base64_decode\([\'"][^\'"]+[\'"]\))\);~msi',
            'id' => 'jsonDecodedVar',
        ],
        [
            'full' => '~if\s?\(file_put_contents\(\$\w{1,50}\.[\'"][^\'"]+[\'"],(base64_Decode\([\'"][^\'"]+[\'"]\))\)\)echo\s?[\'"][^\'"]+[\'"];~msi',
            'id' => 'filePutPureEncodedContents',
        ],
        [
            'full' => '~function\s?(\w{1,50})\((\$\w{1,50})\){for\s?\((\$\w{1,50})\s?=\s?0;\s?\3\s?<=\s?strlen\(\2\)-1;\s?\3\+\+\s?\){(\$\w{1,50})\s?\.=\s?\2{strlen\(\2\)-\3-1};}return\(\4\);}((?:eval\(\1\(\'[^\']+\'\)\);)+)~msi',
            'id' => 'evalFuncReverse',
        ],
        [
            'full' => '~function\s?(\w{1,50})\(\$\w{1,50}\)\s?{return\s?base64_decode\(\$\w{1,50}\);}(?:.*?\1\("[^"]+"\))+~msi',
            'fast' => '~function\s?\w{1,50}\(\$\w{1,50}\)\s?{return\s?base64_decode\(\$\w{1,50}\);}(?:.*?\w{1,50}\("[^"]+"\))+~msi',
            'id' => 'base64decodeFuncs',
        ],
        [
            'full' => '~error_reporting\(\s?0\s?\);\s?(\$\w{1,50})\s?=\s?[\'"]([^\'"]+)[\'"];\s?(\$\w{1,50})\s?=\s?(?:\1\[\d+\]\.?)+;\s?(\$\w{1,50})\s?=\s?eval\s?\(\3\s?\("((?:\\\\x\w{1,50})+)"\s?\([\'"]{1,2}([^"\']+)[\'"]{1,2}\)\)\);\s?create_function\(\'\',\s?\'}\'\.\4\.\'//\'\);~msi',
            'fast' => '~error_reporting\(\s?0\s?\);\s?(\$\w{1,50})\s?=\s?[\'"]([^\'"]+)[\'"];\s?\$\w{1,50}\s?=\s?(?:\$\w{1,50}\[\d+\]\.?)+;\s?(\$\w{1,50})\s?=\s?eval\s?\(\$\w{1,50}\s?\("((?:\\\\x\w{1,5})+)"\s?\([\'"]{1,2}([^"\']+)[\'"]{1,2}\)\)\);\s?create_function\(\'\',\s?\'}\'\.\$\w{1,50}\.\'//\'\);~msi',
            'id' => 'evalCreateFuncWithDictionaryVar',
        ],
        [
            'full' => '~error_reporting\(\s?0\s?\);\s?(\$\w+)\s?=\s?"([^"]+)";(?:\$\w+\s?=\s?(?:\$\w+\[\d+\]\.?)+;)+function\s\w+\((?:\$\w+,?){5}\){\s*return\s?(?:\$\w+\.?){5};}(?:\$\w+\s?=\s?(?:[\'"][^\'"]*[\'"]\.?)+;)+\$\w+\s?=\s?\w+\((?:\$\w+,?){5}\);(?:\$\w+\s?=\s?(?:[\'"][^\'"]*[\'"]\.?)+;)+function\s(\w+)\((?:\$\w+,?){3}\){\s*return\s?(?:\$\w+\.?){3};}\$\w+\s?=\s?((?:\3\((?:(?:\$\w+|\.?[\'"][^"\']*[\'"]\.?)+,?){3}\)\.)+["\']{1,2}([^"\']+)[\'"]{1,2}\.\$\w+);\$\w+\(\'\',\s?\'}\'\.\$\w+\.\'//\'\);~msi',
            'id' => 'evalCreateFuncWithVars',
        ],
        [
            'full' => '~(?(DEFINE)(?\'v\'(?:\$(?:_GET|GLOBALS)\{\2\}[\{\[][a-fx\d]+[\}\]])))error_reporting\([^)]+\);define\(\'([^\']+)\',\s*\'[^\']+\'\);\$(?:_GET|GLOBALS)\[\2\]\s*=\s*explode\(\'([^\']+)\',\s*gzinflate\(substr\(\'(.*)\',([0-9a-fx]+),\s*([0-9\-]+)\)\)\);(?:.{1,250}(?:(?&v)|curl|\\\\[0-9a-fx]+))+[^;]+;(?:\s*(\$\w+\((?:\$\w+\.?)+\);|eval\(\$\w+\);\s*\}\s*function\s*\w+[^1]+!1\);\s*return\s*curl_exec\(\$\w+\);)?[^;]+;)~msi',
            'id' => 'explodeSubstrGzinflate',
        ],
        [
            'full' => '~error_reporting\([^)]+\);header\([^)]+\);ini_set\([^)]+\);ini_set\([^)]+\);define\(\'PASSWD\',\'[^)]+\);define\(\'VERSION\',\'Bypass[^)]+\);define\(\'THISFILE\'[^;]+;define\(\'THISDIR\',[^;]+;define\(\'ROOTDIR\',[^;]+;(((?:\$\w+=\'[^\']+\';)+)((?:\$\w+=str_replace\(\'[^\']+\',\'\',\'[^\']+\'\);)+)(\$\w+)=\$\w+\(\$\w+\(\'[^\']+\'\),\$\w+\(\'[^\']+\'\)\);\4\(((?:\$\w+\.?)+)\);)~msi',
            'id' => 'base64Vars',
        ],
        [
            'full' => '~function\s*(\w+)\(\$\w+,\$\w+\)\s*\{\$\w+=array\(\);for\(\$\w+=0;\$\w+<256;\$\w+\+\+\)(?:[^}]+}){2}return\s*\$res;\s*}\s*function\s*(\w+)\(\)\s*{(?:[^}]+}){12}(?:\$\w+=(?:chr\([0-9b]+\)\.?)+;)+\2\(\);@?eval\(\$\w+\(\1\(\$\{\'[^\']+\'\.(?:\(\'.\'\^\'.\'\)\.?)+}\[\(\'.\'\^\'.\'\)\.\(\'.\'\^\'.\'\)\],\$\w+\("([^"]+)"\)\)\)\);exit;~msi',
            'id' => 'chr0b',
        ],
        [
            'full' => '~@?error_reporting\(0\);\s*@?ini_set\(\'error_log\',NULL\);\s*@?ini_set\(\'log_errors\',0\);\s*(\$\w+)=strrev\([base64_decode\'\.]+\);(\$\w+)=gzinflate\(\1\(\'([^\']+)\'\)\);\s*create_function\("","}\2//"\);~msi',
            'id' => 'createFuncPlugin',
        ],
        [
            'full' => '~((?:\$\w+\s*=\s*str_replace\("[^"]+",\s*"",\s*"[^"]+"\);\s*)+)\s*(eval\((?:\$\w+\()+\'([^\']+)\'\)+;)~msi',
            'id' => 'strreplaceEval',
        ],
        [
            'full' => '~(\$\w+)\s*\s*=\s*"[a-f0-9]{32,40}";\s*(\$\w+)\s*=\s*"[create_fution".]+;\s*(\$\w+)=@?\2\(\'(\$\w+),(\$\w+)\',\'[eval\'\.]+\("\\\\\1=\\\\"\5\\\\";\?>"[gzinflate\.\']+\(\s*[base64_decode\'\.]+\(\4\)+;\'\);\s*@?\$\w+\("([^"]+)",\1\);~msi',
            'id' => 'hackM19',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*strrev\("[create_funtio"\.\s]+\);\s*(\$\w+)\s*=\s*\1\(\'(\$\w+)\',\s*strrev\(\';\)+\w+\$\([bas64_dcode\'\.\s]+\([bzdecompres\'\.\s]+">\?"\([eval\.\'\s]+\)\);\s*\2\("([^"]+)"\);~msi',
            'id' => 'ev404',
        ],
        [
            'full' => '~class\s+(_\w+)\s*{\s*private\s+static\s*\$\w{1,5}\s*;\s*public\s*static\s*function\s*(\w+)[^}]{1,1000}\s*}\s*private\s*static\s*function\s*\w{1,10}\s*\(\s*\)\s*{self::\$\w{1,5}\s*=\s*array\s*\(\s*([^)]+)\s*\);\s*}\s*}\s*class\s+(_\w+)\s*{\s*private\s+static\s*\$\w{1,5}\s*;\s*public\s*static\s*function\s*(\w+)[^}]{1,1000}\s*}\s*private\s*static\s*function\s*\w{1,10}\s*\(\s*\)\s*{self::\$\w{1,5}\s*=\s*array\s*\(\s*([^)]+)\s*\);\s*}\s*}\s*(.{1,5000}exit\s*;\s*})~mis',
            'id' => 'twoHashFunc',
        ],
        [
            'full' => '~(\s*function\s*(\w+)\((\$\w+)\)\s*\{\s*(?:\$\w+\s*=\s*[gzinflatebs64_dco\'\.]+;\s*)+\3\s*=\s*(?:\$\w+\()+\3\)+;\s*return\s*\3;}(\$\w+)\s*=\s*\'([^\']+)\';\s*(\$\w+)\s*=\s*\'\2\';\s*\3\s*=\s*\6\(\'[^)]+\);\s*(\$\w+)\s*=\s*\3\(\'\',\6\(\4\)+;\7\(\);)\s*\w+\(\d+(,\'[^\']+\',\'[^\']+\')?\);~msi',
            'id' => 'setVars',
        ],
        [
            'full' => '~(?:\$\w+=\'[gzuncompresbae64_dtfi\.\']+;\s*)+\$\w+=\$\w+\(\'(\$\w+)\',\'[eval\'\.]+\(\1\);\'\);\s*(\$\w+)=\'([^\']+)\';\s*\$\w+\("\?>"\.(\$\w+\()+\2\)+;~msi',
            'id' => 'createFuncGzB64',
        ],
        [
            'full' => '~(\$\w{1,50})=(?:[\'"][create_funcion]+[\'"]\.?)+;\$\w{1,50}=\1\([\'"](\$\w{1,50})[\'"],(?:[\'"][eval(gzuncomprsb64_d]+[\'"]\.?)+[\'"][decode(]+\2\)+;[\'"]\);\$\w{1,50}\([\'"]([^\'"]+)[\'"]\);~msi',
            'id' => 'createFuncGzB64',
        ],
        [
            'full' => '~(\$\w+)=strrev\(\'[base64_dco]+\'\);\s?(\$\w+)=gzinflate\(\1\(\'([^\']+)\'\)\);\s?create_function\("","}\2//"\);~msi',
            'id' => 'createFuncGzInflateB64',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*(\(?\s*gzinflate\s*\(\s*base64_decode\s*)\(\s*\'([^\']+)\'\s*\)\s*\)\s*\)?\s*;\s*\$\w+\s*=\s*@?create_function\(\'([^\']*)\',\s*(?:\1|\'@?eval\(\4\)[^\']+\')\)\s*;\s*@?\$\w+(?:\(\)|\(\1\));~msi',
            'id' => 'createFuncGzInflateB64',
        ],
        [
            'full' => '~(\$\w+)="((?:\\\\\w+)+)";((\$\w+)=\1\("[^"]+"\);)@(eval\(\1\("[^"]+"\)\);)(\$\w+=(?:\$\w+\[\d+\]\.?)+;)((\$\w+)=(\$\w+)\(\1\("([^"]+)"\),-1\);)((?:\$\w+=(?:\$\w+\[\d+\]\.?)+;)+)@(eval\(\$\w+\(\1\("[^"]+"\)\)\));~msi',
            'id' => 'wsoShellDictVars',
        ],
        [
            'full' => '~error_reporting\(\d+\);(\$\w+)="([^"]+)";(\$\w+)=explode\("([^"]+)","([^"]+)"\);foreach\(\3\sas\s\$\w+=>\$\w+\){\$\w+=preg_split\("//",\$\w+,-1,[^)]+\);\3\[\$\w+\]=implode\("",array_reverse\(\$\w+\)\);}(\$\w+)=explode\("([^"]+)","([^"]+)"\);foreach\(\6\sas\s\$\w+=>\$\w+\){\${\$\w+}=\3\[\$\w+\];}function\s(\w+)\(\$\w+,\$\w+\){\$\w+=\${"[^"]+"}\["([^"]+)"\]\("//",\$\w+,-1,[^)]+\);foreach\(\$\w+\sas\s\$\w+=>\$\w+\){\$\w+\[\$\w+\]=\${"[^"]+"}\["([^"]+)"\]\(\${"[^"]+"}\["([^"]+)"\]\(\$\w+\)\+\$\w+\);}\$\w=\${"[^"]+"}\["([^"]+)"\]\("",\$\w+\);return\s\$\w+;}(\$\w+)=\9\(\14,-2\);@ini_set\(\'[^\']+\',\'[^\']+\'\);((?:\$\w+=(?:\$\w+\[\d+\]\.?)+;)(\$\w+)=(?:\$\w+\[\d+\]\.?)+;)function\s(\w+)\(\$\w+\){\$\w+=\9\(\$\w+,1\);\$\w+=strtr\(\$\w+,"([^"]+)","([^"]+)"\);return\s\$\w+;}((?:\$\w+\.?=(?:\$\w+\[\d+\]\.?)+;)+)(\$\w+)=\${"[^"]+"}\["[^"]+"\]\(\'(?:\$\w+,?)+\',(\$\w+)\(\17\("([^"]+)"\)\)\);@\${"[^"]+"}\["[^"]+"\]\((?:@\$\w+,?)+\);~msi',
            'id' => 'funcDictVars',
        ],
        [
            'full' => '~((\$\w{1,10})\s*=\s*\(\s*[\'"]([^\'"]{40,50000})[\'"]\s*\)\s*;\s*(\$\w{1,10})\s*=\s*base64_decode\s*\(\s*\2\s*\)\s*;)\s*(\$\w{1,10}\s*=\s*fopen\s*[^;]+;\s*echo\s*fwrite[^;]+;\s*fclose[^;]+;)~mis',
            'id' => 'funcFile2',
        ],
        [
            'full' => '~function\s*(\w+)\((\$\w+)\)\s*\{\s*\2=((?:\w+\()+)\2(\)+);\s*for\(\$\w=0;\$\w+<strlen\(\2\);\$\w+\+\+\)\s*\{\s*\2\[\$\w+\]\s*=\s*chr\(ord\(\2\[\$\w+\]\)-(\d+)\);\s*\}\s*return\s*\2;\s*\}eval\(\1\(("[^"]+")\)\);~mis',
            'id' => 'sec7or',
        ],
        [
            'full' => '~error_reporting\(0\);\s*class\s*(\w+)\{\s*private\s*\$\w+=\s*array\(\s*((?:"[^"]+"=>"[^"]+",?\s*)+)\)\s*;\s*public\s*function\s*(\w+)\s*\(\s*\$\w+,\s*\$\w+\s*\)\s*{[^}]+}\s*public\s*function\s*(\w+)\s*\(\$\w+,\$\w+\)\s*{[^}]+}\s*private\s*function\s*\w+\((?:\$\w+,?){7}\)\s*{[^}]+}return\s*array\((?:\$\w+,?){3}\);}}\s*(\$\w+)=new\s*\1;\s*(\$\w+)=\5->\3\(\'tmhapbzcerff\',array\(\'onfr\',\'_qrpbqr\',\'fgeeri\'\)\);\5->\4\(\6,\'\'\);\s*die\(\);~msi',
            'id' => 'classWithArrays',
        ],
        [
            'full' => '~error_reporting\(0\);(\s*(\$\w+)="[asert\."]+;\s*\$(\w+)=\2\(strrev\("([^"]+)"\)\);\s*\$\{\'\3\'\};)~msi',
            'id' => 'assertStrrev',
        ],
        [
            'full' => '~error_reporting\(0\);\$\w+\="[^"]+";\$\w+\=explode\("[^"]+","[^"]+"\);foreach\(\$\w+ as \$\w+\=\>\$\w+\)\{\$\w+\=preg_split\("//",\$\w+,\-1,PREG_SPLIT_NO_EMPTY\);\$\w+\[\$\w+\]\=implode\("",array_reverse\(\$\w+\)\);\}\$\w+\=explode\("[^"]+","[^"]+"\);foreach\(\$\w+ as \$\w+\=\>\$\w+\)\{\$\{\$\w+\}\=\$\w+\[\$\w+\];\}function \w+\(\$\w+,\$\w+\)\{\$\w+\=\$\{"[^"]+"\}\["\w+"\]\("//",\$\w+,\-1,PREG_SPLIT_NO_EMPTY\);foreach\(\$\w+ as \$\w+\=\>\$\w+\)\{\$\w+\[\$\w+\]\=\$\{"[^"]+"\}\["[^"]+"\]\(\$\{"[^"]+"\}\["\w+"\]\(\$\w+\)\+\$\w+\);\}\$\w+\=\$\{"[^"]+"\}\["\w+"\]\("",\$\w+\);return \$\w+;\}\$\w+\=\w+\(\$\w+,\-2\);@ini_set\(\'memory_limit\',\'1024M\'\);(?:\$\w+\=(?:\$\w+\{\d+\}\.?)+;)+function \w+\(\$\w+\)\{\$\w+\=\w+\(\$\w+,(\d+)\);\$\w+\=strtr\(\$\w+,"([^"]+)","([^"]+)"\);return \$\w+;\}(?:\$\w+\.?=(?:\$\w+\{\d+\}\.?)+;)+\$\w+\=\$\{"[^"]+"\}\["\w+"\]\(\'\$\w+,\$\w+,\$\w+,\$\w+\',\$\w+\(\w+\("([^"]+)"\)\)\);@\$\{"[^"]+"\}\["\w+"\]\(@\$\w+,@\$\w+,@\$\w+,@\$\w+,@\$\w+,@\$\w+\);~msi',
            'id' => 'b64strtr',
        ],
        [
            'full' => '~error_reporting\(\d\);function\s(\w{1,50})\(\$\w{1,50},\$\w{1,50}\){if\(file_exists\("[^"]+"\)\){touch\(__FILE__,filemtime\("[^"]+"\)\);}\$\w{1,50}=str_replace\(array\(\'([^\']+)\',\'([^\']+)\'\),array\(\'([^\']+)\',\'([^\']+)\'\),\$\w{1,50}\);\$\w{1,50}=strrev\(\'[base64]+\'\)\."_"\.strrev\(\'[decode]+\'\);\$\w{1,50}=\$\w{1,50}\(\$\w{1,50}\);\$\w{1,50}=strrev\(\'[gzinflate]+\'\);return@\$\w{1,50}\(\$\w{1,50}\);}\s?\$\w{1,50}=\'([^;]+;)([^\']+)">\';preg_match\(\'#\6\(\.\*\)">#\',\$\w{1,50},\$\w{1,50}\);\$\w{1,50}=\$\w{1,50}\[1\];\$\w{1,50}=\1\(\$\w{1,50},\$\w{1,50}\);if\(isset\(\$\w{1,50}\)\){eval\(\$\w{1,50}\);}~msi',
            'id' => 'gzB64strReplaceDataImage',
        ],
        [
            'full' => '~(\$\w{1,50})=array\((?:base64_decode\([\'"][^\'"]+[\'"]\),?){2}base64_Decode\(strrev\(str_rot13\(explode\(base64_decode\([\'"][^\'"]+[\'"]\),file_get_contents\(__FILE__\)\)\[1\]\){4};preg_replace\(\1\[0\],serialize\(eval\(\1\[2\]\)\),\1\[1\]\);exit\(\);\s?\?>\s*([^\s]{1,})~msi',
            'id' => 'serializeFileContent',
        ],
        [
            'full' => '~(function\s\w{1,50}\(\$\w{1,50}\)\s?{\s?global\s(?:\$\w{1,50},?\s*)+;\s*\$\w{1,50}\(\$\w{1,50},\s?\$\w{1,50},\s?\$\w{1,50}\(\)\s?\+\s?\w{1,50}\(\$\w{1,50}\),\s?(?:\$\w{1,50}\s?,?\.?\s*)+\);\s*}\s*global\s?(?:\$\w{1,50},?\s*)+;\s*(?:\$\w{1,50}\s?=\s?\'[^\']+\';\s*)+function\s?\w{1,50}\(\$\w{1,50}\)\s{\s*global\s?(?:\$\w{1,50},?\s*)+;.*?return\s\$\w{1,50}\(\$\w{1,50}\);\s}\s*(?:\$\w{1,50}\s?=\s?\'[^\']*\';\s*)+(?:function\s\w{1,50}\(.*?(?:\$\w{1,50}\s?=\s?\'[^\']*\';\s*)+)+(?:\$\w{1,50}\s\.?=\s\$\w{1,50};\s*)+.*?extract\(\w{1,50}\(get_defined_vars\(\)\)\);)\s*(\$\w{1,50}\(\d\);\s*\$\w{1,50}\(\$\w{1,50},\s?0\);\s*\$\w{1,50}\s=\s\$\w{1,50}\(\$_REQUEST,\s?\$_COOKIE,\s?\$_SERVER\);.*?\$\w{1,50}\(\$\w{1,50}\);\s*echo\s?\$\w{1,50};)~msi',
            'id' => 'globalVarsManyReplace',
        ],
        [
            'full' => '~\$\w{1,50}\s{0,100}=\s{0,100}"([^"]{1,50000})";\s?(\$\w{1,50}\s?=\s?(?:["][^"]{1,5}["]\.?)+;\s?\s?(?:\s?\$\w{1,50}\s?\.?=(?:\s?(?:\s?"[^"]+"|\$\w{1,50})\s?\.?)+;\s?)+)\$\w{1,50}\s?\(\s?\$\w{1,50},((?:\$\w{1,50}\()+\$\w{1,50}\)+),"[^"]{1,100}"\);~msi',
            'id' => 'concatVarsPregReplace',
        ],
        [
            'full' => '~(?:\$\w{1,50}\s?=\s?(?:"[^"]+"\.?)+;)+\s?echo\sjson_encode\(array\([\'"][^"\']+[\'"]=>@\$\w{1,50}\(__FILE__,(\$\w{1,50}\([\'"][^"\']+[\'"]\)\))>0,[\'"][^"\']+[\'"]=>__FILE__\)\);exit;~msi',
            'id' => 'filePutContentsB64Decoded',
        ],
        [
            'full' => '~(\$\w{1,50})\s?=\s?base64_decode\([\'"][^\'"]+[\'"]\);\s?\$\w{1,50}\s?=\s?\$_POST\[[\'"][^\'"]+[\'"]\]\.[\'"][^\'"]+[\'"];\s?\$\w{1,50}\s?=\s?fopen\([\'"][^\'"]+[\'"]\.\$\w{1,50},\s?[\'"]w[\'"]\);\s?fwrite\(\$\w{1,50},\1\);~msi',
            'id' => 'fwriteB64DecodedStr',
        ],
        [
            'full' => '~file_put_contents\(\$_SERVER\[\'[^\']+\'\]\.\'[^\']+\',base64_decode\(\'[^\']+\'\)\);~msi',
            'id' => 'filePutContentsB64Content',
        ],
        [
            'full' => '~((\$\w{1,50})\s?=\s?((?:chr\(\d{1,5}\)\.?)+);)(\$\w{1,50})\s?=\s?(?:\2\[\d{1,5}\]\.?)+;(\$\w{1,50})\s?=\s?(?:\2\[\d{1,5}\]\.?)+;\4\(\5\(null,\s?((?:\2\[\d{1,5}\]\.?)+)\)\);~msi',
            'id' => 'chrDictCreateFunc',
        ],
        [
            'full' => '~(?:function\s\w{1,50}\((?:\$\w{1,50}\,?)+\){return\sstr_replace\((?:\$\w{1,50}\,?)+\);}\s?){3}(\$\w{1,50})\s?=\s?[\'"]([^\'"]+)[\'"];\s?\$\w{1,50}\s?=\s?\w{1,50}\([\'"]([^\'"]+)[\'"],\'\',\1\);\s?(?:\$\w{1,50}\s?=\s?[\'"][^\'"]+[\'"];\s?\$\w{1,50}\s?=\s?\w{1,50}\([\'"][^\'"]+[\'"],\'\',\$\w{1,50}\);\s?){2}\$\w{1,50}\s?=\s?[\'"][^\'"]+[\'"];\s?\$\w{1,50}\s?=\s?\$\w{1,50}\(\$\w{1,50},\$\w{1,50}\.\'\(\'\.\1\.\'\(\'\.\$\w{1,50}\.\'\)\);\'\);\s?\$\w{1,50}\([\'"]([^\'"]+)[\'"]\);~msi',
            'id' => 'strReplaceFuncsEvalVar',
        ],
        [
            'full' => '~\$\w{1,50}\s?=\s?"\\\\x[^"]+";\${\$\w{1,50}}\s?=\s?base64_decode\("(.*?\\\\x[^"]+")\);\s?eval\(".*?\\\\x[^\$]+\$\w{1,50}\\\\"\);"\);~msi',
            'id' => 'B64SlashedStr',
        ],
        [
            'full' => '~(\$\w{1,50})\s?=\s?array\((?:[\'"][base64_dco]+[\'"],?\s?)+\);\s?array_splice\(\1,\s?4,\s?0,\s?8\*8\);\s?(\$\w{1,50})\s?=\s?implode\(\'\',\s?array_reverse\(\1\)\);\s?(\$\w{1,50})\s?=\s?\2\([\'"]([^\'"]+)[\'"]\);\s?eval\(\3\);~msi',
            'id' => 'B64ArrayStrEval',
        ],
        [
            'full' => '~(\$\w{1,50})\s?=\s?[\'"]([^\'"]+)[\'"];\s?\$\w{1,50}\s?=\s?(?:\1\[\d+\]\.?)+;\s?@\$\w{1,50}\((?:\1\[\d+\]\.?)+,(?:\1\[\d+\]\.?)+"\("\.(?:\1\[\d+\]\.?)+\'\([\'"]([^\'"]+)[\'"]\)\);\',"\."\);~msi',
            'id' => 'DictVarsPregReplaceB64',
        ],
        [
            'full' => '~(\$\w+\s*=\s*\'[bs64_dcogzinflate\.\'\s]+;\s*)+(\$\w+)\s*=\s*\'([^\']+)\';\s*eval\((?:\$\w+\()+\2\)+;~msi',
            'id' => 'evalVarB64',
        ],
        [
            'full' => '~(if\s*\(\!function_exists\s*\("([^"]+)"\)\)\s*\{\s*function\s*\2\s*\((\$\w+)\)\s*\{\s*(\$\w+)\s*=\s*"";\s*(\$\w+)\s*=\s*0;\s*\$\w+\s*=\s*strlen\s*\(\3\);\s*while\s*\(\$\w+\s*<\s*\$\w+\)\s*\{\s*if\s*\(\3\[\5\]\s*==\s*\'\s\'\)\s*\{\s*\4\s*\.=\s*"\s";\s*\}\s*else\sif\s*\(\3\[\5\]\s*==\s*\'!\'\)\s*\{\s*\4\s*\.=\s*chr\s*\(\s*\(ord\s*\(\3\[\5\+\d\]\)-ord\s*\(\'A\'\)\)\*16\+\s*\(ord\s*\(\3\[\5\+\d\]\)-ord\s*\(\'a\'\)\)\);\s*\5\s*\+=\s*2;\s*\}\s*else\s*\{\s*\4\s*\.=\s*chr\s*\(ord\s*\(\3\[\5\]\)\+1\);\s*\}\s*\5\+\+;\s*\}\s*return\s*\4;\s*\}\s*\}\s*)eval\s*\(\2\s*\(\'([^\']+)\'\)\);~msi',
            'id' => 'decodeAChar',
        ],
        [
            'full' => '~(\$\w+)="([^"]+)";(\$\w+)="[str_eplac"\.]+";((?:\$\w+\s*=\s*\3\("([^"]+)","","[^"]+"\);)+)(\$\w+)\s*=\s*\$\w+\(\'\',\s*((?:\$\w+\()+\1\)\))\);\6\(\);~msi',
            'id' => 'strReplaceCreateFunc',
        ],
        [
            'full' => '~function\s*(\w+)\((\$\w+)\)\s*\{\s*\$\w+\s*=\s*strlen\(trim\(\2\)+;\s*\$\w+\s*=\s*\'\';\s*(\$\w+)\s*=\s*0;\s*while\s*\(\(\(\$\w+\s*<\s*\$\w+\)+\s*\{\s*(\$\w+)\s*\.=\s*pack\([\'"]C[\'"],\s*hexdec\(substr\(\2,\s*\3,\s*2\)\)\);\s*\3\s*\+=\s*2;\s*\}\s*return\s*\4;\s*\}\s*eval\(\1\([\'"]([0-9a-f]+)[\'"]\)\s*\.\s*\'([^\']+\'\)+;)\s*\'\);~msi',
            'id' => 'evalbin2hex',
        ],
        [
            'full' => '~function\s\w{1,50}\(\$\w{1,50},\s?\$\w{1,50}\)\s?{\s?return;\s?}\s?function\s\w{1,50}\((?:\$\w{1,50}\s?=\s?"",?\s?){2}\)\s?{.*?(?:function\s\w{1,50}\((?:\$\w{1,50},?\s?)+\)\s?{\s?return\s\$\w{1,50};\s?}\s?)+function\s\w{1,50}\(\).*?(?:function\s\w{1,50}\((?:\$\w{1,50},?\s?)+\)\s?{\s?return\s\$\w{1,50};\s?}\s?)+function\s\w{1,50}\(\).*?(?:function\s\w{1,50}\((?:\$\w{1,50},?\s?)+\)\s?{\s?return\s\$\w{1,50};\s?}\s?)+(?:header\(\w{1,50}\([\'"][^\'"]+[\'"]\)\);\s?)+define.*?PDO\(.*?\$\w{1,50}\s?=\s?0;\s?function\s?\w{1,50}\(\$\w{1,50}\)\s?{\s?global.*?function\s(\w{1,50})\(\$\w{1,50}\)\s?{\s?\$\w{1,50}\s?=\s?"";\s?for\s?\(\$\w{1,50}\s?=\s?0;\s?\$\w{1,50}\s?<\s?strlen\(\$\w{1,50}\)\s?-\s?1;\s?\$\w{1,50}\s?\+=2\)\s?{\s?\$\w{1,50}\s?\.=\s?chr\(hexdec\(\$\w{1,50}\[\$\w{1,50}\]\s?\.\s?\$\w{1,50}\[\$\w{1,50}\s?\+\s?1\]\)\s?\^0x66\);\s?}\s?return\s\$\w{1,50};\}(?:.*?(?:function\s\w{1,50}\((?:\$\w{1,50},?\s?)+\)\s?{\s?return\s\$\w{1,50};\s?}\s?)+)+~msi',
            'id' => 'manyFuncsWithCode',
        ],
        [
            'full' => '~(\$[0o]+)="([\\\\x0-9a-f]+)";(\$[0o]+)=@?\1\(\'([^\']+)\',"([\\\\x0-9a-f]+)"\);@?\3\("([^"]+)"\);~msi',
            'id' => 'gzB64Func',
        ],
        [
            'full' => '~(?:(?:session_start|error_reporting|set_time_limit)\(\d*\);\s?)+(?:@?ini_set\([\'"][^\'"]+[\'"],[\'"][^\'"]+[\'"]\);\s?)+((\$\w{1,50})\s?=\s?(?:[\'"][base64_dco]+[\'"]\.?)+;\s(\$\w{1,50})\s?=\s?\2\(((?:[\'"][^\'"]+[\'"]\.?)+)\);)\s?(\$\w{1,50})\s?=\s?array\(((?:(?:\s?\3\((?:[\'"][^\'"]+[\'"]\.?)+\)(?:\.?)?|\3|\2|(?:chr\(\d+\)\.?))+,\s?)+\${(?:chr\(\d+\)\.?)+}\[(?:chr\(\d+\)\.?)+\])\);\s?(?:.*?\5\[\d+\])+~msi',
            'id' => 'dictArrayFuncVars',
        ],
        [
            'full' => '~function\s(\w{1,50})\(\){\$\w{1,50}\s?=\s?[\'"]([^\'"]+)[\'"];\$\w{1,50}\s?=\s?str_rot13\(\$\w{1,50}\);\$\w{1,50}\s?=\s?base64_decode\([\'"]([^\'"]+)[\'"]\);(\$\w{1,50})\s?=\s?@\$\w{1,50}\(\'\',\s?pack\(\'H\*\',\s?\$\w{1,50}\)\);\s?\4\(\);\s?}\1\(\);~msi',
            'id' => 'createFuncPackStrRot13',
        ],
        [
            'full' => '~error_reporting\(0\);\s?(?:\s?function\s(\w{1,50})\((?:\$\w{1,50}\,?\s?){3}\)\s?{\s?return\s?[\'"]{2}\s?\.\s?(?:\$\w{1,50}\s?\.\s?[\'"]{2}\s?\.?\s?)+;\s*}|\s?(?:\w{1,50}:)?(\$\w{1,50})\s?=\s?"([^"]+)";){2}\s?(?:\s?(?:\w{1,50}:)?\$\w{1,50}\s?=\s?\1\((?:\2\[0\d{1,5}\][,.\s\'"]*)+\);\s?)+\s?print_r\(\2\[0\d{1,5}\]\);\s?echo\s?"[^"]+";\s*(\$\w{1,50})=\1\((?:\1\((?:(?:\$\w{1,50}|""),?)+\),?\.?)+\)\."\'([^\'"]+)\'"\.\1\((?:\2\[0\d{1,5}\],?)+\."",\2\[0\d{1,5}\]\);\s?print_r\(\$\w{1,50}\);\s?(?:\$\w{1,50}=\1\((?:\2\[0\d{1,5}\][.,]?)+\);\s?)+\$\w{1,50}=\1\(\1\((?:\$\w{1,50},?)+\),\$\w{1,50},\1\((?:\$\w{1,50},?)+\)\);\s?\$\w{1,50}\(create_function,array\("","}"\.\4\."//"\)\);~msi',
            'id' => 'dictVarsCreateFunc',
        ],
        [
            'full' => '~(?:function\s(\w{1,50})\((?:\$\w{1,50}\,?\s?){3}\)\s?{\s?return\s?[\'"]{2}\s?\.\s?(?:\$\w{1,50}\s?\.\s?[\'"]{2}\s?\.?\s?)+;\s*}\s?|(?:\w{1,50}:)?(\$\w{1,50})\s?=\s?"([^"]+)";\s?){2}(?:\s?\$\w{1,50}\s?=\s?\1\((?:(?:(?:\2\[\d+\])?[,.\s\'"]*)+|(?:\s?\1\((?:\$\w{1,50}[,.\s\'"]*)+\),?)+)\);)+\s?(\$\w{1,50})\s?=\s?\1\((?:\s?\1\((?:\$\w{1,50}[,.\s\'"]*)+\),?)+\)\s?\.\s?"\'([^"]+)\'"\s?\.\s?\1\((?:(?:\2\[\d+\])?[,.\s\'"]*)+\);\s?\$\w{1,50}\(\$\w{1,50},\s?array\(\'\',\s?"}"\s?\.\s?\4\s?\.\s?"//"\)\);~msi',
            'id' => 'dictVarsCreateFunc',
        ],
        [
            'full' => '~function\s(\w{1,50})\((\$\w{1,50})\)\s?{.*?\$\w+\s?=\s?"[^"]+";\$\w{1,50}\s?=\s?str_split\(\$\w{1,50}\);\$\w{1,50}\s?=\s?array_flip\(\$\w{1,50}\);\$\w{1,50}\s?=\s?0;\$\w{1,50}\s?=\s?"";\$\w{1,50}\s?=\s?preg_replace\("[^"]+",\s?"",\s?\$\w{1,50}\);do\s?{(?:\$\w{1,50}\s?=\s?\$\w{1,50}\[\$\w{1,50}\[\$\w{1,50}\+\+\]\];){4}\$\w{1,50}\s?=\s?\(\$\w{1,50}\s?<<\s?2\)\s?\|\s?\(\$\w{1,50}\s?>>\s?4\);\$\w{1,50}\s?=\s?\(\(\$\w{1,50}\s?&\s?15\)\s?<<\s?4\)\s?\|\s?\(\$\w{1,50}\s?>>\s?2\);\$\w{1,50}\s?=\s?\(\(\$\w{1,50}\s?&\s?3\)\s?<<\s?6\)\s?\|\s?\$\w{1,50};\$\w{1,50}\s?=\s?\$\w{1,50}\s?\.\s?chr\(\$\w{1,50}\);if\s?\(\$\w{1,50}\s?!=\s?64\)\s?{\$\w{1,50}\s?=\s?\$\w{1,50}\s?\.\s?chr\(\$\w{1,50}\);}if\s?\(\$\w{1,50}\s?!=\s?64\)\s?{\$\w{1,50}\s?=\s?\$\w{1,50}\s?\.\s?chr\(\$\w{1,50}\);}}\s?while\s?\(\$\w{1,50}\s?<\s?strlen\(\$\w{1,50}\)\);return\s?\$\w{1,50};}\s?.*?function\s(\w{1,50})\(\){\$\w{1,50}\s?=\s?@file_get_contents\(\w{1,50}\(\)\);.*?(\$\w{1,50})\s?=\s?"([^"]{1,20000})";.*?\4\s?=\s?@unserialize\(\1\(\4\)\);.*?(function\s(\w{1,50})\(\$\w{1,50}=NULL\){foreach\s?\(\3\(\)\s?as.*?eval\(\$\w{1,50}\);}}}).*?(\7\(\);)~msi',
            'id' => 'decodedFileGetContentsWithFunc',
        ],
        [
            'full' => '~((?:\$\w{1,50}\s?\.?=\s?"\\\\[^"]+";)+)((?:\$\w{1,50}=\$\w{1,50}\(\$\w{1,50}\);){3})(\$\w{1,50})=[\'"]([^\'"]+)[\'"];(\$\w{1,50})=[\'"]([^\'"]+)[\'"];if\(function_exists\(\$\w{1,50}\)\){\$\w{1,50}=@\$\w{1,50}\(\'\3,\$\w{1,50}\',(\$\w{1,50}\(\$\w{1,50}\()\5\)\)\);if\(\$\w{1,50}\)\3=@\$\w{1,50}\(\3,\$\w{1,50}\);\s?}else{.*?};if\(function_exists\(\$\w{1,50}\)\)\s?{\$\w{1,50}=@\$\w{1,50}\("",\7\3\)\)\);if\(\$\w{1,50}\)@\$\w{1,50}\(\);}else{.*?};~msi',
            'id' => 'createFuncVarsCode',
        ],
        [
            'full' => '~(\$\w+)=\'[preg_lac.\']+\';\1\(\'[#\~\\\\1\'.e]+\',\'([^,]+)\',\'1\'\);~msi',
            'id' => 'pregConcat',
        ],
        [
            'full' => '~(?(DEFINE)(?\'c\'\s*/\*[^\*]+\*/\s*))(?:\$\{"[^"]+"(?&c)?\^(?&c)?"[^"]+"\}\s*=\s*"[^"]+"\s*(?&c)?\^(?&c)?\s*"[^"]+";\s*)+\$\{"[^"]+"(?&c)?\^(?&c)?"[^"]+"\}\s*=\s*\(\s*\$\{"[^"]+"(?&c)?\^(?&c)?"[^"]+"\}\(\s*\$\{"[^"]+"(?&c)?\^(?&c)?"[^"]+"\}\s*\(\s*\'([^\']+)\'\)\s*\)\s*\)\s*;\s*\$\{"[^"]+"(?&c)?\^(?&c)?"[^"]+"\}="[^"]+"\s*(?&c)?\^(?&c)?\s*"[^"]+";\s*\$\{"[^"]+"(?&c)?\^(?&c)?"[^"]+"\}\s*=\s*@?\$\{"[^"]+"(?&c)?\^(?&c)?"[^"]+"\}\(\'[^\']+\',\s*"[^"]+"\s*(?&c)?\^(?&c)?\s*"[^"]+"\)\s*;@?\${"[^"]+"(?&c)?\^(?&c)?"[^"]+"\}\(\$\{"[^"]+"(?&c)?\^(?&c)?"[^"]+"\}\);~msi',
            'id' => 'xoredStrings',
        ],
        [
            'full' => '~\$\w+\s*=\s*\'([^\']+)\';\s*//base64 - gzinflate - str_rot13 - convert_uu - gzinflate - base64~msi',
            'id' => 'commentWithAlgo',
        ],
        [
            'full' => '~error_reporting\(0\);\s*set_time_limit\(0\);\s*ini_set\(\'memory_limit\',\s*\'-1\'\);\s*if\(isset\(\$_POST\[\'pass\']\)\)\s*{\s*function\s*[^}]+}\s*file_put_contents\((\$\w+)\."[^"]+",\s*gzdeflate\(file_get_contents\(\1\),\s*\d\)\);\s*unlink\(\1\);\s*copy\(\'\.htaccess\',\'[^\']+\'\);\s*(\$\w+)\s*=\s*base64_decode\("[^"]+"\);\s*(?:\$\w+\s*=\s*str_replace\(\'[^\']+\',\s*[^;]+;\s*)+\$\w+\s*=\s*\$\w+;\s*(\$\w+)\s*=\s*"<\?php[^;]+;\s*\?>";\s*(\$\w+)\s*=\s*fopen\(\'[^\']+\',\'w\'\);\s*fwrite\(\4,\s*\3\);\s*fclose\(\4\);\s*(\$\w+)\s*=\s*base64_decode\("[^"]+"\);\s*(\$\w+)\s*=\s*fopen\(\'[^\']+\',\s*\'w\'\);\s*fwrite\(\6,\s*\5\);\s*fclose\(\6\);\s*echo\s*"[^"]+";\s*}\s*function\s*(\w+)[^}]+}[^}]+[\s}]+[^!]+!+\';[^!]+!+\';\s*}\s*exit\(\);\s*}\s*function\s*\w+\(\){~msi',
            'id' => 'fileEncryptor',
        ],
        [
            'full' => '~function\s?\w{1,50}\(\$\w{1,50}\)\s*{(\$\w{1,50}=true;)?((?:\$\w{1,50}\s?=\s?[\'"](?:base64_(?:de|en)code|[\\\\xa-f0-9]+)[\'"];)+).*?exit;}}\w{1,50}\([\'"][^\'"]+[\'"]\);~msi',
            'id' => 'base64decodedFuncContents',
        ],
        [
            'full' => '~((?:if\(!function_exists\(base64_[end]+code\)\)\{function\s*(\w+)[^{]+({([^{}]*+(?:(?3)[^{}]*)*+)})\}\s*else\s*\{function\s*\2\((\$\w+)\)\s*\{\s*global\s*base64_[end]+code;return\s*base64_[end]+code\(\5\);\}\})+).*?((?:function\s*(\w+)\(\$\w+\)\{return\s*\w+\(\$\w+\);\s*\}\s*)+).*?(eval\(gzinflate\(\7\(\'([^\']+)\'\)\)\);)~msi',
            'id' => 'definedB64',
        ],
        [
            'full' => '~(?(DEFINE)(?\'v\'(?:(?:\$\{)*"GLOBALS"\}\["\w+"\]\}?|\$\w+|"\w+")))(?:(?&v)\s*=\s*"\w+";\s*)+(?:if\s*\(isset\(\$_GET\["[^"]+"\]\)\)\s*\{\s*echo\s*(?:"[^"]+"|\$_GET\["[^"]+"\]);\s*die;\s*\}\s*)*(?:(?&v)\s*=\s*"\w+";\s*)*function\s*(\w+)\(\$\w+,\s*\$\w+\s*=\s*\'\'\)\s*\{\s*(?:(?&v)\s*=\s*(?&v);\s*)+[^\^]+\^\s*(?&v)\[(?&v)\];\s*\}\s*\}\s*return\s*(?&v);\s*\}\s*(?:\$\w+\s*=\s*"[^"]+";)?\s*(?&v)\s*=\s*"[^"]+";\s*(?:(?&v)\s*=\s*"[^"]+";)?\s*(?:\$\w+ = "D";)?\s*((?&v))\s*=\s*"([^"]+)";(?:\s*(?&v)\s*=\s*[\'"][^\'"]*[\'"];\s*)+(?:foreach\s*\(array\(([\d\s,]+)\)\s*as\s*(?&v)\)\s*\{\s*(?:(?&v)\s*=\s*"\w+";\s*)*\s*(?&v)\s*\.=\s*(?&v)\[(?&v)\];\s*\}\s*(?:\s*(?&v)\s*=\s*[\'"][^\'"]*[\'"];\s*)?)+\s*(?&v)\s*=\s*(?&v)\([creat_fuion"\'\s\.]+\);\s*(?&v)\s*=\s*(?&v)\("[^"]*",\s*(?&v)\s*\(\2\((?&v)\((?&v)\),\s*"([^"]+)"\)\)\);\s*(?&v)\(\);~msi',
            'id' => 'B64Xored',
        ],
        [
            'full' => '~(\$\w{1,50})\s?=\s?<<<FILE\s*([\w\s+/=]+)FILE;\s*(\$\w{1,50}\s?=\s?(base64_decode\(\1\));)~msi',
            'id' => 'B64AssignedVarContent',
        ],
        [
            'full' => '~(\$\w{1,50})\s?=\s?\'([^\']+)\';((?:\$\w{1,50}\s?=\s?(?:\1\[[()\d/+*-]+\]\.?)+;)+)\$\w{1,50}\s?=\s?"[^"]+";(?:\$\w{1,50}\s?\.?=\s?\$\w{1,50};)+@?\$\w{1,50}\s?=\s?\$\w{1,50}\(\(\'\'\),\s?\((\$\w{1,50})\)\);@?\$\w{1,50}\(\);~msi',
            'id' => 'dictVarsWithMath',
        ],
        [
            'full' => '~(\$\w{1,50})\s?=\s?"([^"]+)";\s*class\s?(\w+){\s*var\s?\$\w{1,50};\s*function\s__construct\(\)\s?{\s?\$this->\w{1,50}\(\d+\);\s*}\s*function\s?(\w{1,50})\(\$\w{1,50}\)\s?{\s?\$\w{1,50}\s?=\s?\$_SERVER\[\'HTTP_USER_AGENT\'\];\s?if\s?\(\s?preg_match\(\'/\s?Apple\(\.\*\)\s?\\\\\(/is\',.*?str_replace.*?explode.*?\'0+\';(?:.*?function\s\w{1,50}\([^)]+\){.*?(?:unpack|pack|\$this->|fmod|chr))+.*?return\s\$\w{1,50};[\s}]+(\$\w{1,50})\s?=\s?hex2bin\(\1\);\s?\$\w{1,50}\s?=\s?new\s?\3\(\d+\);\s?(\$\w{1,50})\s?=\s?\$\w{1,50}->\4\(\5\);\s?eval\(\6\);~msi',
            'id' => 'classDecryptedWithKey',
        ],
        [
            'full' => '~((\$\w+)\s*=\s*str_rot13\(base64_decode\(\'([^\']+)\'\)\);\s*(\$\w+)\s*=\s*str_rot13\(base64_decode\(\'([^\']+)\'\)\);\s*\$\w+\s*=\s*\'[^\']+\';)\s*preg_match\(\$\w+\(\$\w+\(\'[^\']+\'\)\),\s*file_get_contents\(__FILE__\),\s*\$\w+\);\s*(eval\(\$\w+\(\$\w+\(\'([^\']+)\'\)\)\);)\s*eval\(\$\w+\(\$\w+\(\'[^\']+\'\)\)\);\s*unset\(\$\w+,\s*\$\w+\);\s*__halt_compiler\(\);\s*\?>\s*\[PHPkoru_Info\]\s*[^\]]+\]\s*\[PHPkoru_Code\]\s*([^\[]+)\[/PHPkoru_Code\]~msi',
            'id' => 'PHPkoru',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"([^"]+)";\s*(\$\w+)\s*=\s*\$this->(\w+)\("([^"]+)"\);\s*(\$\w+)\s*=\s*\3\(\'\',\s*\$this->\4\(\1\)\);\s*\6\(\);~msi',
            'id' => 'JoomlaInject',
        ],
        [
            'full' => '~((\$\w{1,50})\s*=\s*[\'"]([^"\']+)[\'"];\s*)\$\w{1,50}\s*=\s*fopen\([^)]+\);\s*\$\w{1,50}\s*=\s*fwrite\s?\(\$\w{1,50}\s*,\s*(base64_decode\(\2\))\);~msi',
            'id' => 'fwriteB64Content',
        ],
        [
            'full' => '~(\$\w{1,50})\s*=\s*"([^"]+)";\s*(\$\w{1,50})\s*=\s*base64_decode\(\1\);\s*(\$\w{1,50})\s*=\s*base64_decode\("([^"]+)"\);\s*(\$\w{1,50}\s*=(\s*\3\s*\.\s*\4);)~msi',
            'id' => 'B64concatedVars',
        ],
        [
            'full' => '~(\$\w{1,50})\s*=\s*"(\\\\[\w\\\\]+)";\s*(\$\w{1,50})\s*=\s*@\1\([\'"](\$\w{1,50})[\'"]\s*,\s*"(\\\\[\w\\\\]+)"\);\s*@\3\(([\'"][^\'"]+[\'"])\);~msi',
            'id' => 'slashedCreateFunc',
        ],
        [
            'full' => '~(\$\w{1,50})\s*=\s*"([^"]+)";((?:\$\w{1,50}\s*=\s*(?:\$\w{1,50}\[\d+\]\.?)+;)+@?(?:\$\w{1,50}(?:\[\d+\]\.?)?[,()]*)+;)~msi',
            'id' => 'varDictCreateFunc',
        ],
        [
            'full' => '~@call_user_func\(create_function\([\'"]\s*[\'"],gzinflate\(base64_decode\([\'"\\\\]{1,3}([^\'"\\\\]+)[\'"\\\\]{1,3}\)\)\),[^)]+\);~msi',
            'id' => 'callFuncGzB64',
        ],
        [
            'full' => '~@?(\$\w{1,50})\s*=\s*"([^"]+)";@?(\$\w{1,50})\s*=\s*array\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\);@?(\$\w{1,50})\s*=\s*"([^"]+)";@?(\$\w{1,50})\s*=\s*[\'"]{2};for\s*\(\$\w{1,50}\s?=\s?0;\s?\$\w{1,50}\s?<\s?6;\s?\$\w{1,50}\+\+\)\s*{@?\$\w{1,50}\s?=\s?@?\3\[@?\$\w{1,50}\]\s*;@?\12\.=\s?@?\1\[@?\$\w{1,50}\]\s?;\s*}@?\12\(((?:"\\\\x[^"]+"\.?)+)\);~msi',
            'id' => 'assertDictVarEval',
        ],
        [
            'full' => '~function\s+(\w{1,50})\((\$\w{1,50})\)\s*{\s*\$\w{1,50}\s?=\s?"[^"]+";\s?(?:(?:\$\w{1,50}\s?=\s?)+"";)+.*?<<\s?2.*?<<\s?6.*?!=\s?64.*return\s?\$\w{1,50};}\s?function\s+(\w{1,50})\(\$\w{1,50}\){\s*return\s\1\(\$\w{1,50}\);}\s*eval\(\3\(gzinflate\(\3\("([^"]+)"\),0\)+~msi',
            'id' => 'B64FuncEvalGz',
        ],
        [
            'full' => '~(\$\w{1,50})\s*=\s*"([^"]+)";\s*(\$\w{1,50})\s?=\s?(?:[\d\-+*])+;\s*\$\w{1,50}\s?=\s?[\'"]base[\'"]\s?\.\s?\3\.\s?[\'"]_decode[\'"];\s*\$\w{1,50}\s?=\s?\$\w{1,50}\(\$\w{1,50}\);(\$\w{1,50})\s?=\s?@?gzinflate\(\$\w{1,50}\);@?eval\(("\?>"\.?)?\4\);~msi',
            'id' => 'B64Gz',
        ],
        [
            'full' => '~function\s*(\w+)\((\$\w+)\)\s*\{\s*(?:\2=gzinflate\(base64_decode\(\2\)\);|\$\w+\s*=\s*base64_decode\(\2\);\s*\2\s*=\s*gzinflate\(\$\w+\);)\s*for\(\$\w+=0;\$\w+<strlen\s*\(\2\);\$\w+\+\+\)\s*\{\s*\2\[\$\w+\]\s*=\s*chr\(ord\(\2\[\$\w+\]\)(-?\d+)\);\s*\}\s*return\s*\2;\s*\}eval\(\1\s*\("([^"]+)"\)\);~msi',
            'id' => 'deltaOrd',
        ],
        [
            'full' => '~(?(DEFINE)(?\'g\'(?:\$\{)?\$\{"(?:G|\\\\x47)(?:L|\\\\x4c)(?:O|\\\\x4f)(?:B|\\\\x42)(?:A|\\\\x41)(?:L|\\\\x4c)(?:S|\\\\x53)"\}\["[^"]+"\](?:\})?))(?:(?&g)="[^"]+";)+function\s*(\w+)\(\$\w+\)\s*\{(?&g)="[^"]+";(?&g)=gzinflate\(base64_decode\((?&g)\)\);\$\w+="[^"]+";for\((?&g)=0;(?&g)<strlen\((?&g)\);(?&g)\+\+\)\s*\{\$\w+="[^"]+";(?&g)="[^"]+";(?&g)\[\$\{\$\w+\}\]=chr\(ord\((?&g)\[(?&g)\]\)([\-\+]\d+)\);\}return\$\{\$\w+\};\}eval\(\2\("([^"]+)"\)\);~msi',
            'id' => 'deltaOrd',
        ],
        [
            'fast' => '~<\?php\s(?:eval\(")?ob_start\(\);(?:"\))?\s\?>(.*?)<\?php\s(eval\(")?if\(!function_exists\("([^"]+)"\)\)\{function\s\3\(\)\{(\$[^=]+)=str_replace\(array\(([^)]+)\),array\(([^)]+)\),ob_get_clean\(\)\);for\((\$[^=]+)=1,(\$[^=]+)=ord\(\4\[0\]\);\7<strlen\(\4\);\7\+\+\)\4\[\7\]=chr\(ord\(\4\[\7\]\)-\8-\7\);\4\[0\]=\'\s\';return\s\4;\}\}(?:"\))?\s\?>(.*?)<\?php\s(\$[^=]+)=\3\(\);\s*eval\(\10\s*\)\s*(\?>\s*)+~msi',
            'full' => '~(?:<\?php\s*\$\w+\s*=\s*"[^"]+";\s*\?>\s*)?<\?php\s(?:eval\(")?ob_start\(\);(?:"\))?\s\?>(.*?)<\?php\s(eval\(")?if\(!function_exists\("([^"]+)"\)\)\{function\s\3\(\)\{(\$[^=]+)=str_replace\(array\(([^)]+)\),array\(([^)]+)\),ob_get_clean\(\)\);for\((\$[^=]+)=1,(\$[^=]+)=ord\(\4\[0\]\);\7<strlen\(\4\);\7\+\+\)\4\[\7\]=chr\(ord\(\4\[\7\]\)-\8-\7\);\4\[0\]=\'\s\';return\s\4;\}\}(?:"\))?\s\?>(.*?)<\?php\s(\$[^=]+)=\3\(\);\s*eval\(\10\s*\)\s*(\?>\s*)+~msi',
            'id' => 'outputBuffer',
        ],
        [
            'fast' => '~\s*(\$\w+)\s*=\s*[base64_decode"\./\-\*]+;.*?\1(?:.{0,300}?\1\((?:\$\w+|"[^"]+")\))+[^\}]+\}~msi',
            'full' => '~(?:\$\w+\s*=\s*\$_SERVER\["DOCUMENT_ROOT"\]\."/";)?\$\w+\s*=\s*"[^"]+";(?:\$\w+\s*=\s*\$_SERVER\["DOCUMENT_ROOT"\]\."/";)?\s*(\$\w+)\s*=\s*[base64_decode"\./\-\*]+;.*?\1(?:.{0,300}?\1\((?:\$\w+|"[^"]+")\))+[^\}]+\}~msi',
            'id' => 'doorwayInstaller',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"([^"]+)";\s*(\$\w+)\s*=\s*str_replace\((\w),"","[^"]+"\);\s*\3\(\'[eval\'.]+\(\'[base64_dcod\'.]+\(\'[gzinflate.\']+\(\'[base64_dcod\'.]+\(\'[^\)]+\)[^;]+;~msi',
            'id' => 'strReplaceAssert',
        ],
        [
            'full' => '~(?:(\$\{\'GLOBALS\'\}\[\'[^\']+\'\])=\'\w+\';\s*)+.*\1\};\}~msi',
            'id' => 'anaLTEAMShell',
        ],
        [
            'full' => '~(\$\w+)=\'[function_exis\'\.]+;\$\w+=\'[charodet\'\.]+;(\$\w+)=\'[eval\'\.]+;(\$\w+)=\'[gzinflate\'\.]+;(if\(!\1\(\'[base64_dcon\'\.]+\)\)({([^{}]*+(?:(?5)[^{}]*)*+)})else{function\s*[^}]+\}\})+(\$\w+)=\'[create_funion\'\.]+;(\$\w+)\s*=\s*\7\(\'([^\']+)\',\2\.\'\(\'\.\3\.\'\(\'\.\'[^(]+\(\9\)\'\.\'\)\'\.\'\)\'\.\';\'\);\8\("([^"]+)"\);~msi',
            'id' => 'zeuraB64Gzinflate',
        ],
        [
            'full' => '~function\s*(\w+)\((\$\w+)\)\{((?:(\$\w+)\s*=\s*str_replace\(\'[^\']+\',\'[^\']+\',\'[^\']+\'\);\s*)+)return\s*(\$\w+\(\'\',\$\w+\(\2\)\);)\}(\$\w+)\s*=\'([^\']+)\';(\$\w+)=\1\(\6\);\8\(\);~msi',
            'id' => 'strReplaceFunc',
        ],
        [
            'full' => '~(\$\w+)=array\(array\(((?:\'[^\']+\',?)+)\)\);\s*(?:/\*[^\*]+\*/)?(\$\w+)(?:/\*[^\*]+\*/)?[^\?]+\?>\s*\.\s*base64_decode\s*\(\s*str_rot13\s*\(\s*join\s*\(\s*\'\'\s*,\s*\3\s*\)\s*\)\s*\)\s*\.\s*\'[^\']+\'\s*\);(?:/\*[^\*]+\*/)?\s*(\$\w+)=array_walk\s*\(\1,\$\w+\);~msi',
            'id' => 'arrayMapB64',
        ],
        [
            'full' => '~preg_replace\(\'/\.\+\/e\',str_replace\("([^"]+)","([^"])*","([^"]+)"\),\'\.\'\);~msi',
            'id' => 'pregReplaceStrReplace',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*(base64_decode\("([^"]+)"\));\s*(\$\w+)\s*=\s*(base64_decode\("([^"]+)"\));\s*echo\s*"[^"]+";\s*if\s*\(\$\w+\s*==\s*"[^"]+"\)\s*\$\w+\s*=\s*"[^"]+"\.\4\."[^"]+"\.\1;~msi',
            'id' => 'echoB64',
        ],
        [
            'full' => '~(\$\w+\s*=\s*"[^"]+"\^"[^"]+";)+\$\w+\s*=\s*\(?(?:@?\$\w+\()+\'([^\']+)\'\)+;(\$\w+\s*=\s*"[^"]+"\^"[^"]+";)+(\$\w+)\s*=\s*\(?(?:@?\$\w+\()+\'\$\w+\',"[^"]+"\^"[^"]+"\);@?\4\(\$\w+\);~msi',
            'id' => 'createFuncXored',
        ],
        [
            'full' => '~(\$\w{1,50})\s?=\s?array\(((?:\'[^\']\',?)+)\);\s?(?:\$\w{1,50}\s?=\s?(?:\1\[\d+\]\.?)+;\s?)+(\$\w{1,50})\s?=\s?((?:\$\w{1,50}\.?)+)\'(\$\w{1,50})\'\.(?:\1\[\d+\]\.?)+;\5\s?=\s?"([^"]+)";\s?@?eval\(\3\);~msi',
            'id' => 'evalDictArrayConcat',
        ],
        [
            'full' => '~(?:(?:\$\w+="[^"]+"|\$\w+="[a-f0-9\\\\x]+"\^"[a-f0-9\\\\x]+"|\$\w+=(?:"[^"]+"\.?)+);)+\$\w+=(?:\$\w+\.?)+;\s*(\$\w+)\("/(\w+)/e",(\$\w+),"\2"\);(?:\s*\1\("/(\w+)/e",(\$\w+),"\4"\);)?~msi',
            'id' => 'pregReplaceXored',
        ],
        [
            'full' => '~\$\w{1,5}=\'([a-z0-9+/=]{1,100}\s[a-z0-9+/=\s]+)\';(\$\w)=["\']_COOK[\\\\x0-9]{1,10}";\s*if\(!empty\(\${\2}\[["\']key["\']\]\)\){(?:\$\w=[^;]{1,30};\s*){1,5}for\([^)]{1,40}\)(?:\$\w\[?\]?=[^;]{1,30};\s*){1,5}for\([^)]{1,40}\){[^}]{1,150}}if[^;]{1,50};\s*if\(\(\$\w=@?gzinflate\(\$\w\)\)&&\(md5\(substr\(\$\w,\d,\$\w\)\)===\'([a-f0-9]{32})\'\)\){\$\w{1,5}=[^;]{1,100};if\(PHP_VERSION<\'5\'\){[^}]{1,1000}}@create_function\(\'\',"[^"]{1,100}"\.\$\w{1,5}\.\'{\'\);}}\s*DIE\(.{1,500}>"\);~msi',
            'id' => 'base64EncryptedGz',
        ],
        [
            'full' => '~error_reporting\(0\);function\s*(\w+)\((\$\w+)\)\s*\{\s*return\s*strtr\(\2,\s*\'((?:(?=(?:\\\\)*)\\\\.|.)*?)\',\s*\'((?:(?=(?:\\\\)*)\\\\.|.)*?)\'\s*\);\s*\s*\}eval\(\1\(\'([^\']+)\'\)\);(\$\w+)\s*=\s*((?:\$\w+\[\d+\]\()+\'[^\']+\'\)+;)\$\w+\[\d+\]\(\6\);~msi',
            'id' => 'Bloos3rpent',
        ],
        [
            'full' => '~(@?eval\(@?gzinflate\(base64_decode\(preg_replace\(\'([^\']+)\',\s*\'([^\']*)\',\s*\'([^\']+)\'\)+;)\s*(preg_replace\("/(\w+)/e".\s*\'\')@?eval\(@?gzinflate\(\w+\(base64_decode\((preg_replace\(\'([^\']+)\',\s*\'([^\']*)\',\s*)\'([^\']+)\'\)+;(\'\',"\6"\);)~msi',
            'id' => 'doublePregReplace',
        ],
        [
            'full' => '~(\$\w+)="([^"]+)";(\$\w+)=array\(((?:\d+,?)+)\);(\$\w+)="([^"]+)";(\$\w+)="";for\s*\((\$\w+)=0;\8<\d+;\8\+\+\)\{(\$\w+)=\3\[\8\]\s*;\s*\7\.=\s*\1\[\9\]\s*;\s*\}\7\("eval\(base64_decode\(gzinflate\(base64_decode\(\5\),0\)\)\)"\);~msi',
            'id' => 'zeura2',
        ],
        [
            'full' => '~(\$\w+)="([\\\\a-fx0-9])+";(\$\w+)="([\\\\a-fx0-9])+";(\$\w+)=\1\("",\3\("([^"]+)"\)\);\5\(\);~msi',
            'id' => 'createFuncEscaped',
        ],
        [
            'full' => '~error_reporting\s*\(0\);\s*function\s*([^\(]+)\(\)\s*\{\s*\$[^= ]+\s*=\s*[0-9a-fx]+;\s*\$[^= ]+\s*=\s*func_get_args\s*\(\);\s*if\s*\(+\$[^}]+}\s*if\s*\(+[^{]+\{\s*return\(+parse_str\("[^=]+=([^"]+)",[^}]+\}\s*\}\s*function\s*([^(]+)\(\)\{\s*\$[^=]+=func_get_args\(\);\s*\$[^=]+=[0-9a-fx]+;(\s*if\s*\([^}]+\})+\s*\}\s*function\s*([^(]+)\(\$[^)]+\)\s*{[^}]+\}\s*return\s*\$[^;]+;\s*\}\s*eval\(\5\(\1\([0-9a-fx]+,[0-9a-fx]+\)+;~msi',
            'id' => 'maskedDeltaOrd',
        ],
        [
            'full' => '~(\$\w{1,50})\s?=\s?(?:chr\(-?\d{1,5}[+\-*^/]-?\d{1,5}\)\s?\.?)+;\s?(\$\w{1,50})\s?=\s?"((?:[^-]-m\s+){10}[^"]+)";\s?\$\w{1,50}\s?=\s?\w{1,50}\(\s?\1\s?\(\s?array\("-m\s",\s?PHP_EOL\),\s?"",\s?\2\)\);\s?function\s?\w{1,50}\s?\((\$\w{1,50})\s?\){\s?.*?\$\w{1,50}\(\4\);}\s?\$\w{1,50}\s?=\s?(?:chr\(-?\d{1,5}[+\-*^/]-?\d{1,5}\)\s?\.?)+;\s?(\$\w{1,50})\s?=\s?"([^"]+)";\s?(\$\w{1,50})\s?=\s?array\(\);\s?for\s?\((\$\w+)\s?=0;\s?\8\s?<\s?256;\s?\+\+\8\)\s?{\s?\7\s?\[\8\]\s?=\s?\8;\s?}\s?\$\w{1,50}\s?=\s?0;\s?for\s?\(\8\s?=0;\s?\8\s?<\s?256;\s?\+\+\8\)\s?{.*?ord\(\$\w{1,50}\s?\[\$\w{1,50}\s?%\s?(\d+)\]\)\)\s?%\s?256;.*?for\s?\(.*?<(\d+);\s?\+\+\$\w{1,50}\).*?}\s?\$\w{1,50}\s?=\s?\4;\s?\$\w{1,50}\s?=\s?(?:chr\(-?\d{1,5}[+\-*^/]-?\d{1,5}\)\s?\.?)+;\s?\$\w{1,50}\("/\w+/e",\s?(?:chr\(-?\d{1,5}[+\-*^/]-?\d{1,5}\)\s?\.?)+,"\w+"\);~msi',
            'id' => 'decodeStrMultiForDict',
        ],
        [
            'full' => '~(?:\$\w{1,50}\s?=\s?\'[^\']+\';\s?)+(?:\$\w{1,50}\s?=\s?str_replace\([\'"][^\'"]+[\'"],\s?["\']{2},\s?[\'"][^\'"]+[\'"]\);\s?){2}(\$\w{1,50})\s?=\s?\$\w{1,50}\(\$\w{1,50}\([\'"][^\'"]+[\'"]\),\s?\$\w{1,50}\([\'"]([^\'"]+)[\'"]\)\);\s?\1\(((?:\$\w{1,50}\s?\.?)+)\);~msi',
            'id' => 'B64ConcatedStrVars',
        ],
        [
            'full' => '~\$\w{1,50}\s?=\s?(\w{1,50})\s?\(array\((?:\d+,?)+\)\);\s?\$\w{1,50}\s?=\s?\1\(array\((?:\d+,?)+\)\);\s?\$\w{1,50}\s?=\s?fopen\(\$\w{1,50},\s?\1\(array\((?:\d+,?)+\)\)\);\s?\$\w{1,50}\s?=\s?fputs\(\$\w{1,50},\s?\$\w{1,50}\);\s?fclose\(\$\w{1,50}\);\s?function\s?\1\(\s?array\s?(\$\w{1,50})\)\s?{\s?if\(\2\)\s?{\s?foreach\s?\(\2\s?as\s?\$\w{1,50}\)\s?{\s?\$\w{1,50}\s?\.=\s?chr\(\$\w{1,50}\);\s?}\s?}\s?return\s?\$\w{1,50};\s?}~msi',
            'id' => 'chrFuncVars',
        ],
        [
            'full' => '~((?:\$\w{1,50}\s?=\s?(?:"[^"]+"\.?)+;)+)\$\w{1,50}\((?:"[^"]+"\.?)+,((?:\$\w{1,50}\()+(?:"[^"]+"\.?)+\)\))\s?,\s?(?:"[^"]+"\.?)+\);~msi',
            'id' => 'concatVarsFuncs',
        ],
        [
            'full' => '~\$GLOBALS\[\'(\w+)\'\];\s*global\s*\$\1;\s*\$\1=\$GLOBALS;(\$\1\[\'(\w+)\']="([^"]+)";)\s*(?:@?\$\1\[(\$\1\[\'\3\'\]\[\d+\]\.?)+\]\s*=(?:\s*(?:\$\1\[\'\3\'\]\[\d+\]\.?)+|\$_POST|\$_COOKIE);\s*)+(?:.{1,120}\$\1\[\'\3\'\])+[^}]+\}exit\(\);\}~msi',
            'id' => 'globalDictVar',
        ],
        [
            'full' => '~\$\w+\s*=\s*\'(\w+)\'\^[^;\']+;\s*(\$\w+)\s*=\s*\w+\&\'[^\';]+\';\s*.*?\2\&\s*[^;]+;\s*\$\w+\s*=\s*\$\w+\&\$\w+;\s*\$\w+\s*=\s*[^;]+;\s*(?:\$\w+\s*=\s*\$\w+\&\$\w+;\s*)+if\s*\(\!(?:\$\w+\s*\()+[^;]+;\s*\'[^\']+\';~msi',
            'id' => 'garbageVars',
        ],
        [
            'full' => '~\$\w+\s*=(?:\s*chr\(-?\d+\^-?\d+\)\s*\.?\s*)+;\s*\$\w+\s*=\s*(?:<<<\'(\w+)\'\s*(.*?)\1|"([^"]+)");\s*\$\w+\s*=\s*(\w+)\((?:\s*\$\w+\s*\(\s*array\("([^"]+)"\),"",\$\w+\)|\s*\$\w+\s*\(\$\w+\))\);\s*function\s*\4\s*\(\$\w+\)\s*\{\s*(?:\$\w+=(?:chr\(-?\d+\^-?\d+\)\s*\.?)+;\s*)+\$\w+=\&\$\w+;\s*\$\w+\.=\$\w+;return\s*\$\w+\(\$\w+\);\}\s*\$\w+\s*=(?:\s*chr\(-?\d+\^-?\d+\)\s*\.?)+;\s*\$\w+\s*=\s*"([^"]+)";\s*(?:\s*\$\w+\s*=\s*array\(\);)?(?:(?:\s*for\s*\(\$\w+=0;\s*\$\w+<\d+;\s*\+\+\$\w+\)\s*\{\s*[^}]+\}(?:\s*\$\w+\s*=\s*(?:0;|\$\w+;))+)+|for\(\$\w+\s*=\s*0;\$\w+<\d+;\+\+\$\w+\)\{\s*\$\w+\{\s*\$\w+\}=\$\w+\{\s*\$\w+\}\^\$\w+\{\s*\$\w+%\d+\};\}\s*\$\w+\s*=\s*\$\w+;)\s*\$\w+\s*=\s*(?:chr\(-?\d+\^-?\d+\)\s*\.?\s*)+;\s*\$\w+\("/(\w+)/e",\s*(?:chr\(-?\d+\^-?\d+\)\s*\.?\s*)+,"\7"\);~msi',
            'id' => 'chrMinXor',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*"([^;]+;)";\s*@assert\(\1\);~msi',
            'id' => 'assertUrlDecode',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*array\(\'([^\)]+)\'\);\$\w+\s*=\s*array\(\'[base64_dco\'\.,]+\)\s*;\s*\$\w+\s*=\s*array\([gzuncompres\'\.,]+\)\s*;\s*(?:\$\w+\s*=\s*\$\w+\[\d\]\.\$\w+\[\d\];\s*)+eval\((?:\$\w+\()+implode\(\'\',\s*\1\)+;~msi',
            'id' => 'implodeB64Gz',
        ],
        [
            'full' => '~((?:\$\w+\s*=\s*"\w";\s*)+)((?:\$\w+\s*=(?:\s*\$\w+\s*\.?)+;\s*)+)(eval\((?:\$\w+\()+"[^"]+"\)+;)~msi',
            'id' => 'X12',
        ],
        [
            'full' => '~(\$\w+)\s*=\s*function\((\$\w+)\)\s*\{\s*return\s*strtr\(\2,\s*"([^"]+)",\s*"([^"]+)"\);\s*\};\$\w\s+=\s*\$\w+\("([^"]+)"\);\$\w+\s*=\s*\$\w+\(\);\$\w+\s*=\s*\$\w+\[\1\("([^"]+)"\)\];foreach\s*\(\$\w+\s*as\s*\$\w+\s*=>\s*\$\w+\)\s*\{[^}]+\}(?:if\s*\([^}]+})+\}(\$\w+)\s*=\s*\$\w+\("",\s*(?:\$\w+\()+"([^"]+)"\)+;\7\(\);~msi',
            'id' => 'WpNightmare',
        ],
        [
            'full' => '~preg_replace\(\'/(\w+)/e\',strrev\(\'\)\)\\\\\'([^\']+)\'\([base64_dco(val]+\'\),\'\1\'\);~msi',
            'id' => 'pregB64Strrev',
        ],
        [
            'full' => '~global\s(\$[^;]+);if\(!defined\([\'"][^\'"]+[\'"]\)\){define\([\'"][^\'"]+[\'"],__FILE__\);function\s?([^(]+)\((\$[^,]+),(\$[^=]+)=[\'"]{2}\){global\s?\1;\3=base64_decode\(\3\);if\(empty\(\3\)\)\s?return\s?[\'"]{2};if\(\4==[\'"]{2}\){return\s?\~\3;}else{(\$[^=]+)=\1\[\'([^\']+)\'\]\(\3\);\4=\1\[\'([^\']+)\'\]\(\4,\5,\4\);return\s?\3\^\4;}}}((?:(?:\1\[\'[^\']+\'\]=\2\(\'[^\']+\',\'[^\']*\')\);)+)(?:\1\[\'[^\']+\'\]=isset[^;]+;)+(eval\(\1\[\'([^\']+)\'\]\(\'([^\']+)\'\)\);)return;\?>~msi',
            'id' => 'utfCharVarsFuncEval',
        ],
        [
            'full' => '~(?:\$\w{1,50}\s?=\s?[\'"][^\'"]+[\'"];\s?)+(\$\w{1,50})\s?=\s?(?:\d+[\+]*)+;.*?\$\w{1,50}\s?=\s?(\w+)\([\'"][^\'"]+[\'"],\s?\1,\s?[\'"][^\'"]+[\'"]\);.*?(\$\w{1,50})\s?=\s?(\$\w{1,50})\(\'\$\w{1,50}\',\s?(\$\w{1,50})\((\$\w{1,50})\((\$\w{1,50}),\s?[\'"](\d+)[\'"]\)\)\);(?:\$\w{1,50}\s?=\s?[\'"][^\'"]+[\'"];\s?)+\$\w{1,50}\(\$\w{1,50},\$\w{1,50}\([\'"]{2},\s?\3\(\$\w{1,50}\(\5\(\6\(\7,\s?[\'"](\d+)[\'"]\)\)\)\)\),\$\w{1,50}\);(?:\$\w{1,50}\s?=\s?[\'"][^\'"]+[\'"];)+\s?function\s\2\(.*return\s\$\w{1,50};}(?:\$\w{1,50}\s?=\s?[\'"][^\'"]+[\'"];\s?)+~msi',
            'id' => 'manyVarFuncCreateFuncWrap',
        ],
        /*[
            'full' => '~class\s*(\w+)\s*{\s*function\s*__construct\(\)\s*\{\s*(\$\w+)\s*=\s*\$this->(\w+)\(\$this->\w+\);\s*\2\s*=\s*\$this->(\w+)\(\$this->(\w+)\(\2\)\);\s*\2\s*=\s*\$this->(\w+)\(\2\);\s*if\(\2\)\s*\{\s*\$this->(\w+)\s*=\s*\2\[\d\];\s*\$this->(\w+)\s*=\s*\2\[\d\];\s*\$this->\w+\s*=\s*\2\[\d\];\s*\$this->(\w+)\(\2\[\d\],\s*\2\[\d\]\);\s*\}\s*\}\s(?:function\s*\w+\((?:(?:\$\w+),?\s?){0,3}\)\s*\{\s*(?:\$this->\w+\s*=\s*\$\w+;\s*\$this->\w+\s*=\s*\$\w+;\s*\$this->\w+\s*=\s*\$this->\3\(\$this->\w+\);\s*\$this->\w+\s*=\s*\$this->\5\(\$this->\w+\);\s*\$this->\w+\s*=\s*\$this->\w+\(\);\s*if\(strpos[^{]+{[^}]+}\s*\}\s*|\$\w+\s*=\s*(?:\$this->\w+\[\d\]\.?)+;\s*(?:\$\w+\s*=\s*@?\$\w+\((?:\'\',\s*)?(?:(?:\$\w+),?\s?){0,3}\);)?\s*(?:return\s*\$\w+(?:\((?:"[^"]+",\s*"",\s*\$\w+)?\))?;)?\s*\}\s*|\$\w+\s*=\s*strlen\(\$\w+\)\s*\+\s*strlen\(\$\w+\);\s*while\(strlen\(\$\w+\)\s*<\s*\$\w+\)\s*\{\s*\$\w+\s*=\s*ord\(\$\w+\[\$this->\w+\]\)\s*-\s*ord\(\$\w+\[\$this->\w+\]\);\s*\$\w+\[\$this->\w+\]\s*=\s*chr\(\$\w+\s*%\s*\(2048/8\)\);\s*\$\w+\s*\.=\s*\$\w+\[\$this->\w+\];\s*\$this->\w+\+\+;\s*\}\s*return\s*\$\w+;\s*\}\s*|\$this->\w+\s*=\s*\$this->\w+\(\$this->\w+,\s*\$this->\w+,\s*\$this->\w+\);\s*\$this->\w+\s*=\s*\$this->\w+\(\$this->\w+\);\s*return\s*\$this->\w+;\s*\}\s*))+var\s*\$\w+;\s*var\s*\$\w+\s*=\s*0;\s*(?:var\s*\$\w+\s*=\s*array\([\'gzinflatecr_utobs64dtkp, ]+\);\s*)+var\s*\$\w+\s*=\s*\'([^\']+)\';\s*var\s*\$\w+\s*=\s*\'([^\']+)\';\s*\}\s*new\s*\1\(\);~msi',
            'id' => 'classDecoder',
        ],
        [
            'full' => '~if\(isset\(\$_POST\[\'\w+\'\]\)\){echo[\s\'\w]+;\s*exit\(\);}\s*if\(isset\(\$_COOKIE\)\){(\$\w+)=\$_COOKIE;\(count\(\1\)==\d+&&in_array\(gettype\(\1\)\.count\(\1\),\1\)\)\?\(\(\1\[\d+\]=\1\[\d+\]\.\1\[\d+\]\)&&\(\1\[\d+\]=\1\[\d+\]\(\1\[\d+\]\)\)&&\(\1=\1\[\d+\]\(\1\[\d+\],\1\[\d+\]\(\1\[\d+\]\)\)\)&&\1\(\)\):\1;}\s*if\(!isset\(\$_POST\[\'\w+\'\]\)&&!isset\(\$_GET\[\'\w+\'\]\)\){exit\(\);}\s*(?:(\$\w+)\[\d+\]=\'\w+\';)+\s*if\(isset\(\$_POST\[\'\w+\'\]\)\){\$\w+=\$_POST\[\'\w+\'\];}else{\$\w+=\$_GET\[\'\w+\'\];}\s*\$\w+\s*=\s*array_flip\(str_split\(\'(\w+)\'\)\);\$\w+\s*=\s*str_split\(md5\(\$\w+\)\.md5\(\$\w+\)\);\$\w+\s*=\s*array\(\);\$\w+\s*=\s*\'\';\s*foreach\s*\(\$\w+\s*as\s*\$\w+\s*=>\s*\$\w+\)\s*{while\s*\(1\)\s*{if\(isset\(\$\w+\[\$\w+\[\$\w+\]\]\)\){\$\w+\[\$\w+\]\+\+;}else\{\$\w+\[\$\w+\[\$\w+\]\]=\'\';break;}}}\s*foreach\s*\(\$\w+\s*as\s*\$\w+\s*=>\s*\$\w+\)\s*{\$\w+\s*\.=\s*\$\w+\[\$\w+\];}\s*eval\(trim\(base64_decode\(base64_decode\(\$\w+\)\)\)\);~mis',
            'fast' => '~if\(isset\(\$_POST\[\'\w+\'\]\)\){echo[\s\'\w]+;\s*exit\(\);}\s*if\(isset\(\$_COOKIE\)\){(\$\w+)=\$_COOKIE;\(count\(\1\)==\d+&&in_array\(gettype\(\1\)\.count\(\1\),\1\)\)\?\(\(\1\[\d+\]=\1\[\d+\]\.\1\[\d+\]\)&&\(\1\[\d+\]=\1\[\d+\]\(\1\[\d+\]\)\)&&\(\1=\1\[\d+\]\(\1\[\d+\],\1\[\d+\]\(\1\[\d+\]\)\)\)&&\1\(\)\):\1;}\s*if\(!isset\(\$_POST\[\'\w+\'\]\)&&!isset\(\$_GET\[\'\w+\'\]\)\){exit\(\);}\s*(?:(\$\w+)\[\d+\]=\'\w+\';)+\s*if\(isset\(\$_POST\[\'\w+\'\]\)\){\$\w+=\$_POST\[\'\w+\'\];}else{\$\w+=\$_GET\[\'\w+\'\];}\s*\$\w+\s*=\s*array_flip\(str_split\(\'(\w+)\'\)\);\$\w+\s*=\s*str_split\(md5\(\$\w+\)\.md5\(\$\w+\)\);\$\w+\s*=\s*array\(\);\$\w+\s*=\s*\'\';\s*foreach\s*\(\$\w+\s*as\s*\$\w+\s*=>\s*\$\w+\)\s*{while\s*\(1\)\s*{if\(isset\(\$\w+\[\$\w+\[\$\w+\]\]\)\){\$\w+\[\$\w+\]\+\+;}else\{\$\w+\[\$\w+\[\$\w+\]\]=\'\';break;}}}\s*foreach\s*\(\$\w+\s*as\s*\$\w+\s*=>\s*\$\w+\)\s*{\$\w+\s*\.=\s*\$\w+\[\$\w+\];}\s*eval\(trim\(base64_decode\(base64_decode\(\$\w+\)\)\)\);~mis',
            'id' => 'scriptWithPass',
        ],*/

        /*************************************************************************************************************/
        /*                                          JS patterns                                                      */
        /*************************************************************************************************************/

        [
            'full' => '~((<script[^>]*>)\s*.{0,300}?)?(eval\()?String\.fromCharCode\(([\d,\s]+)\)(?(3)\);+|)(\s*.{0,300}?</script>)?~msi',
            'fast' => '~String\.fromCharCode\([\d,\s]+\)~msi',
            'id'   => 'JS_fromCharCode',
        ],
        [
            'full' => '~(?:eval\()?unescape\(\'([^\']+)\'\)\);\s{0,50}eval\(unescape\(\'([^\']+)\'\)\s{0,50}\+\s{0,50}\'([^\']+)\'\s{0,50}\+\s{0,50}unescape\(\'[^\']+\'\)\);~msi',
            'fast' => '~unescape\(\'([^\']+)\'\)\);\s{0,50}eval\(unescape\(\'([^\']+)\'\)\s{0,50}\+\s{0,50}\'([^\']+)\'\s{0,50}\+\s{0,50}unescape\(\'[^\']+\'\)\);~msi',
            'id'   => 'JS_unescapeContentFuncWrapped',
        ],
        [
            'full' => '~var\s*(\w+)=\s*\[((?:\'[^\']+\',?)+)\];\(function\(\w+,\w+\)\{var\s*\w+=function\(\w+\)\{while\(--\w+\)\{\w+\[\'push\'\]\(\w+\[\'shift\'\]\(\)\);\}\};.*?\(\1,(0x\w+)\)\);var\s*(\w+)=function\s*\((\w+),(\w+)\)\s*\{\5=\5-0x\d+;var\s*\w+=\w+\[\5\];if\(\4\[\'\w+\']===undefined\)\{\(function\(\)\{var\s*(\w+);try\{var\s*(\w+)=Function\(\'[^;]++;\'\);\7=\8\(\);\}catch\(\w+\)\{\7=window;\}var\s*\w+=\'[^\']+\';\7\[\'atob\'\]\|\|\(\7\[\'atob\'\]=function\(\w+\)\{[^}]+\}return\s*\w+;\}\);\}\(\)\);var\s*\w+=function\(\w+,\w+\)\{var\s*\w+=.+?String\[\'fromCharCode\'\].+?return\s*\w+;\};\4\[\'\w+\'\]=\w+;\4\[\'\w+\'\]=\{\};\4\[\'\w+\'\]=!!\[\];\}var\s*\w+=\4\[\'\w+\'\]\[\w+\];.+?((.+?\4\(\'0x\d+\',\'[^\']+\'\)).+?)+[^\s]+~msi',
            'fast' => '~var\s*(\w+)=\s*\[((?:\'[^\']+\',?)+)\];\(function\(\w+,\w+\)\{var\s*\w+=function\(\w+\)\{while\(--\w+\)\{\w+\[\'push\'\]\(\w+\[\'shift\'\]\(\)\);\}\};.*?var\s*(\w+)=function\s*\((\w+),(\w+)\)\s*\{\4=\4-0x\d+;var\s*\w+=\w+\[\4\];if\(\3\[\'\w+\']===undefined\)\{\(function\(\)\{var\s*(\w+);try\{var\s*(\w+)=Function\(\'[^;]++;\'\);\6=\7\(\);\}catch\(\w+\)\{\6=window;\}var\s*\w+=\'[^\']+\';\6\[\'atob\'\]\|\|\(\6\[\'atob\'\]=function\(\w+\)\{[^}]+\}return\s*\w+;\}\);\}\(\)\);var\s*\w+=function\(\w+,\w+\)\{var\s*\w+=.+?String\[\'fromCharCode\'\].+?return\s*\w+;\};\3\[\'\w+\'\]=\w+;\3\[\'\w+\'\]=\{\};\3\[\'\w+\'\]=!!\[\];\}var\s*\w+=\3\[\'\w+\'\]\[\w+\];.+?((.+?\3\(\'0x\d+\',\'[^\']+\'\)).+?)+[^\s]+~msi',
            'id'   => 'JS_ObfuscatorIO',
        ],
        [
            'full' => '~<script\s(?:language|type)=[\'"](?:text/)?javascript[\'"]>\s*(?:(?:<!--.*?-->)?\s?<!--\s*)?document\.write\((?:unescape\()?[\'"]([^\'"]+)[\'"]\)\)?;(?:\s?//-->)?\s*</script>~msi',
            'id'   => 'JS_documentWriteUnescapedStr',
        ],
        [
            'full' => '~eval\(function\(p,a,c,k,e,(?:d|r)\)\{.*?}\(\'(.*)\', *(\d+), *(\d+), *\'(.*?)\'\.split\(\'\|\'\),\d,\{\}\)\);~msi',
            'id'   => 'JS_deanPacker',
        ],
        [
            'full' => '~\(function\s*\(\$,\s*document\)\s*({([^{}]*+(?:(?1)[^{}]*)*+)})\)\(\(function\s*\((\w),\s*(\w)\)\s*\{\s*function\s*(\w)\((\w+)\)\s*\{\s*return\s*Number\(\6\)\.toString\(36\)\.replace\(/\[0\-9\]/g,\s*function\s*\((\w)\)\s*\{\s*return\s*String\.fromCharCode\(parseInt\(\7,\s*10\)\s*\+\s*65\);\s*\}\s*\);\s*\}\s*var\s*\w+\s*=\s*\{\s*\$:\s*function\s*\(\)\s*\{\s*var\s*\w+\s*=\s*\{\};\s*[^}]+\}\s*return\s*\w;\s*\}\s*\};\s*\3\s*=\s*\3\.split\(\'\+\'\);\s*for\s*\(var\s*\w\s*=\s*0;\s*\w\s*<\s*(\d+);\s*\w\+\+\)\s*\{\s*\(function\s*\(\w\)\s*\{\s*Object\.defineProperty\(\w,\s*\5\(\w\),\s*\{\s*get:\s*function\s*\(\)\s*\{\s*return\s*\w\[\w\]\[0\]\s*\!==\s*\';\'\s*\?\s*\4\(\w\[\w\]\)\s*:\s*parseFloat\(\w\[\w\]\.slice\(1\),\s*10\);\s*\}\s*\}\);\s*\}\(\w\)\);\s*\}\s*return\s*\w;\s*\}\(\'([^\']+)\',\s*function\s*\(\w\)\s*\{\s*for\s*\(var\s*(\w)\s*=\s*\'([^\']+)\',\s*(\w)\s*=\s*\[([^\]]+)\],\s*\w\s*=\s*\'\'[^{]+\{\s*var\s*(\w)\s*=\s*\10\.indexOf\(\w\[\w\]\);\s*\12\.indexOf\(\w\[\w\]\)\s*>\s*\-1\s*&&\s*0\s*===\s*\12\.indexOf\(\w\[\w\]\)\s*&&\s*\(\w\s*=\s*0\),\s*\14\s*>\s*-1\s*&&\s*\(\w\s*\+=\s*String\.fromCharCode\(\w\s*\*\s*\10\.length\s*\+\s*\14\),\s*\w\s*=\s*1\);\s*\}\s*return\s*\w;\s*\}\)\),\s*\(function\s*\(\w\)\s*\{\s*var\s*_\s*=\s*{};\s*for\s*\(\w\s*in\s*\w\)\s*\{\s*try\s*\{\s*_\[\w\]\s*=\s*\w\[\w\]\.bind\(\w\);\s*\}\s*catch\s*\(\w\)\s*\{\s*_\[\w\]\s*=\s*\w\[\w\];\s*\}\s*\}\s*return\s*_;\s*\}\)\(document\)\)~msi',
            'id'   => 'JS_objectDecode',
        ],
        /*************************************************************************************************************/
        /*                                          PYTHON patterns                                                 */
        /*************************************************************************************************************/

        [
            'full' => '~eval\(compile\(zlib\.decompress\(base64\.b64decode\([\'"]([^\'"]+)[\'"]\)\),[\'"]<string>[\'"],[\'"]exec[\'"]\)\)~msi',
            'id'   => 'PY_evalCompileStr',
        ],
    ];

    private $full_source;
    private $prev_step;
    private $cur;
    private $obfuscated;
    private $max_level;
    private $max_time;
    private $run_time;
    private $fragments;
    private $grabed_signature_ids;
    private $active_fragment;
    private $excludes;

    public function __construct($text, $origin_text = '', $max_level = 30, $max_time = 5)
    {
        $this->text         = $text;
        $this->full_source  = $text;

        if ($this->defineSpecificObfuscator($text, $origin_text)) {
            $this->text         = $origin_text;
            $this->full_source  = $origin_text;
        }

        $this->max_level            = $max_level;
        $this->max_time             = $max_time;
        $this->fragments            = [];
        $this->grabed_signature_ids = [];
        $this->excludes             = [];
    }

    private function getPreviouslyDeclaredVars($string, $level = 0)
    {
        $foundVar = false;
        foreach ($this->fragments as $frag => $fragment) {
            if ($foundVar || strpos($frag, '$codelock_lock') !== false) {
                break;
            }

            $subject = '';
            $pos     = strpos($fragment, $string . '=') ?: strpos($fragment, $string . ' ');
            if ($pos !== false && strpos(substr($fragment, $pos + strlen($string)), '$') !== 1) {
                $subject = substr($fragment, $pos);
            } else {
                $pos = strpos($frag, $string . '=') ?: strpos($frag, $string . ' ');
                if ($pos !== false) {
                    $subject = substr($frag, $pos);
                } else {
                    $pos = strpos($this->full_source, $string . '=') ?: strpos($this->full_source, $string . ' ');
                    if ($pos !== false) {
                        $subject = substr($this->full_source, $pos);
                    } else {
                        continue;
                    }
                }
            }

            if (@preg_match_all('~(\$\w{1,40})\s*=\s*((\(*(base64_decode\s*\(|pack\s*\(\'H\*\',|convert_uudecode\s*\(|htmlspecialchars_decode\s*\(|stripslashes\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|eval\s*\()+((?:(["\'])((.*?[^\\\\])??((\\\\\\\\)+)?+)\6[^;]+)|(?:\$\w+)\)*;*))|((["\'])((.*?[^\\\\])??((\\\\\\\\)+)?+)\12));~msi', $subject, $matches, PREG_SET_ORDER) > 0) {
                foreach ($matches as $m) {
                    if ($m[1] !== $string) {
                        continue;
                    }
                    if (isset($m[12]) && $m[12] !== '') {
                        $str = substr(@$m[2], 1, -1);
                        $foundVar = true;
                    }
                    if (isset($m[5]) && $m[5] !== '') {
                        $str = $this->unwrapFuncs($m[2], $level + 1);
                        $foundVar = true;
                    }

                    $this->fragments[$this->active_fragment] = str_replace($m[0], '', $this->fragments[$this->active_fragment]);
                    break;
                }
            }
        }
        return $str;
    }

    private function defineSpecificObfuscator($text, $origin_text)
    {
        if (strpos($origin_text, '#!/') === 0                                                                                                       //not a php file
            || strpos($origin_text, '0=__FILE__;')                                             &&
                (strpos($origin_text, ';return;?>') || strpos($origin_text, 'This file is protected by copyright law and provided under'))  //lockit1 || evalFileContentBySize
            || strpos($origin_text, 'The latest version of Encipher can be obtained from')  && strpos($origin_text, '\'@ev\'));')           //EvalFileContent
            || strpos($origin_text, 'substr(file_get_contents(__FILE__),')                  && strpos($origin_text, '__halt_compiler();')   //EvalFileContentOffset
            || strpos($text, 'create_function(\'\', base64_decode(@stream_get_contents(')   && strpos($text, '@fopen(__FILE__,')            //wpKey (eval)
            || strpos($origin_text, '//base64 - gzinflate - str_rot13 - convert_uu - gzinflate - base64')                                          //
        ) {
            return true;
        }

        $text_wo_ws = str_replace(' ', '', $text);
        if (strpos($text_wo_ws, '=file(__FILE__);eval(base64_decode(')      && strpos($text_wo_ws, '));__halt_compiler();') //zeura hack
            || strpos($text_wo_ws, 'define(\'__LOCALFILE__\',__FILE__);')   && strpos($text_wo_ws, '__halt_compiler();')    //obf_20200527_1
            || strpos($text_wo_ws, '");$cvsu=$gg') || strpos($text_wo_ws, '$cyk=$cyd[')                                     //TinkleShell
        ) {
            return true;
        }

        return false;
    }

    private function checkObfuscatorExcludes($str, $type = false, $matches = [])
    {
        switch ($type) {
            case '':
                if(strpos($str, '# Malware list detected by AI-Bolit (http') !== false) {
                    return '';
                }
                if(strpos($str, '#Malware list detected by AI-Bolit(http') !== false) {
                    return '';
                }
                if(strpos($str, '<div class="header">Отчет сканера ') !== false) {
                    return '';
                }
                if (strpos($str, '$default_action="FilesMan"') !== false) {
                    return '';
                }
                break;
            case 'echo':
                if (preg_match('~\$_[GPRC](?:OST|ET|EQUEST|OOKIE)~ms', $matches[0])) {
                    return '';
                }
                if (!isset($matches[5]) || $matches[5] === '') {
                    return '';
                }
                break;
            case 'eval':
                if (strpos($matches[0], 'file_get_contents') !== false) {
                    return '';
                }
                if (preg_match('~\$_[GPRC](?:OST|ET|EQUEST|OOKIE)~ms', $matches[0])) {
                    return '';
                }
                if (strpos($matches[0], '=> array(\'eval(base64_decode(\')') !== false) {
                    return '';
                }
                if (@$matches[6] === '\'";') {
                    return '';
                }
                break;
        }
        return $type;
    }

    public function getObfuscateType($str)
    {
        $btlimit = ini_get('pcre.backtrack_limit');
        $reclimit = ini_get('pcre.recursion_limit');
        $str = preg_replace('~\s+~', ' ', $str);
        $l_UnicodeContent = Helpers::detect_utf_encoding($str);
        $ret = '';
        if ($l_UnicodeContent !== false) {
            if (function_exists('iconv')) {
                $str = iconv($l_UnicodeContent, "CP1251//IGNORE", $str);
            }
        }
        if ($this->checkObfuscatorExcludes($str) === '') {
            return '';
        }
        ini_set('pcre.backtrack_limit', self::PCRE_BACKTRACKLIMIT);
        ini_set('pcre.recursion_limit', self::PCRE_RECURSIONLIMIT);
        foreach (self::$signatures as $signature) {
            $fast_regexp = isset($signature['fast']) ? $signature['fast'] : $signature['full'];
            if (isset($this->excludes[$str]) && in_array($signature['id'], $this->excludes[$str])) {
                continue;
            }

            if (preg_match($fast_regexp, $str, $matches)) {
                $ret = $this->checkObfuscatorExcludes($str, $signature['id'], $matches);
                break;
            }
        }
        ini_set('pcre.backtrack_limit', $btlimit);
        ini_set('pcre.recursion_limit', $reclimit);
        return $ret;
    }

    private function getObfuscateFragment($str, $type)
    {
        foreach (self::$signatures as $signature) {
            if ($signature['id'] == $type && preg_match($signature['full'], $str, $matches)) {
                return $matches;
            }
        }
        return '';
    }

    public function getFragments()
    {
        if (count($this->fragments) > 0) {
            return $this->fragments;
        }
        return false;
    }

    public function getGrabedSignatureIDs()
    {
        return array_keys($this->grabed_signature_ids);
    }

    private function grabFragments()
    {
        if ($this->cur === null) {
            $this->cur = $this->text;
        }
        $str = $this->cur;
        reset(self::$signatures);
        while ($sign = current(self::$signatures)) {
            $regex = $sign['full'];
            if (preg_match($regex, $str, $matches)) {
                $this->grabed_signature_ids[$sign['id']] = 1;
                $this->fragments[$matches[0]] = $matches[0];
                $str = str_replace($matches[0], '', $str);
            } else {
                next(self::$signatures);
            }
        }
    }

    private function deobfuscateFragments()
    {
        $prev_step = '';
        if (!count($this->fragments)) {
            return;
        }
        $i = 0;
        foreach ($this->fragments as $frag => $value) {
            if ($frag !== $value) {
                continue;
            }
            $this->active_fragment = $frag;
            $type = $this->getObfuscateType($value);

            while ($type !== '' && $i < 50) {
                $match  = $this->getObfuscateFragment($value, $type);
                if (!is_array($match)) {
                    break;
                }
                $find   = $match[0] ?? '';
                $func   = 'deobfuscate' . ucfirst($type);

                try {
                    $temp = @$this->$func($find, $match);
                } catch (Exception $e) {
                    $temp = '';
                }
                if ($temp !== '' && $temp !== $find) {
                    $value = str_replace($find, $temp, $value);
                } else {
                    $this->excludes[preg_replace('~\s+~', ' ', $value)][] = $type;
                    $this->fragments[$frag] = $value;
                    $type = $this->getObfuscateType($value);
                    continue;
                }

                $this->fragments[$frag] = $value;
                $type = $this->getObfuscateType($value);
                $value_hash = hash('sha256', $value);
                if ($prev_step === $value_hash) {
                    break;
                }
                $prev_step = $value_hash;
                $i++;
            }
            $this->fragments[$frag] = Helpers::postProcess($this->fragments[$frag]);
        }
    }

    public function deobfuscate($hangs = 0, $prev_step = '')
    {
        $btlimit = ini_get('pcre.backtrack_limit');
        $reclimit = ini_get('pcre.recursion_limit');
        ini_set('pcre.backtrack_limit', self::PCRE_BACKTRACKLIMIT);
        ini_set('pcre.recursion_limit', self::PCRE_RECURSIONLIMIT);
        $deobfuscated   = '';
        $this->run_time = microtime(true);
        $this->cur      = $this->text;

        $this->grabFragments();
        $this->deobfuscateFragments();

        $deobfuscated = $this->cur;

        if (count($this->fragments) > 0 ) {
            foreach ($this->fragments as $fragment => $text) {
                $deobfuscated = str_replace($fragment, $text, $deobfuscated);
            }
        }

        $deobfuscated = Helpers::postProcess($deobfuscated);

        if (substr_count(substr($deobfuscated, 0, 400), 'base64_decode(\'') > 3) {
            $deobfuscated = preg_replace_callback('~base64_decode\(\'([^\']+)\'\)~msi', static function ($matches) {
                return "'" . base64_decode($matches[1]) . "'";
            }, $deobfuscated);
        }

        if ($this->getObfuscateType($deobfuscated) !== '' && $hangs < 6) {
            $this->text = $deobfuscated;
            if ($prev_step === hash('sha256', $deobfuscated)) {
                return $deobfuscated;
            }
            $deobfuscated = $this->deobfuscate(++$hangs, hash('sha256', $deobfuscated));
        }
        ini_set('pcre.backtrack_limit', $btlimit);
        ini_set('pcre.recursion_limit', $reclimit);
        return $deobfuscated;
    }

    public static function getSignatures()
    {
        return self::$signatures;
    }

    public function unwrapFuncs($string, $level = 0)
    {
        $res = '';
        $close_tag = false;

        if (trim($string) == '') {
            return '';
        }
        if ($level > 100) {
            return '';
        }
        if ((($string[0] === '\'') || ($string[0] === '"')) && (substr($string, 1, 2) !== '?>')) {
            if($string[0] === '"' && preg_match('~\\\\x\d+~', $string)) {
                return stripcslashes($string);
            }
            $end = -2;
            if ($string[-3] === '\'') {
                $end = -3;
            }
            return substr($string, 1, $end);
        }

        if ($string[0] === '$') {
            preg_match('~\$\w{1,40}~', $string, $string);
            $string  = $string[0];
            return $this->getPreviouslyDeclaredVars($string, $level);
        }

        $pos      = strpos($string, '(');
        $function = substr($string, 0, $pos);
        $arg      = $this->unwrapFuncs(substr($string, $pos + 1), $level + 1);

        if (strpos($function, '?>') !== false || strpos($function, "'.") !== false) {
            $function = str_replace(["'?>'.", '"?>".', "'?>' .", '"?>" .', "'."], '', $function);
            $close_tag = true;
        }
        $function = str_replace(['@', ' '], '', $function);
        $safe = Helpers::convertToSafeFunc($function);

        if ($safe) {
            if ($function === 'pack') {
                $args = explode(',', $arg);
                $args[0] = substr(trim($args[0]), 0, -1);
                $args[1] = substr(trim($args[1]), 1);
                $res = @$function($args[0], $args[1]);
            } elseif ($function === 'unserialize') {
                $res = Helpers::unserialize($arg);
            } elseif ($function === 'str_replace') {
                $args = explode(',', $arg);
                $args[0] = substr(trim($args[0]), 0, -1 );
                $args[1] = substr(trim($args[1]), 0);
                if (trim($args[1]) === 'null') {
                    $args[1] = null;
                }
                $args[2] = $this->unwrapFuncs(trim($args[2]), $level + 1) ?? $args[2];
                $res = @$function($args[0], $args[1], $args[2]);
            } else if ($function === 'chr') {
                $res = @$function((int)$arg);
            } else {
                $res = @$function($arg);
            }
        } else {
            $res = $arg;
        }
        if ($close_tag) {
            $res = '?> ' . $res;
            $close_tag = false;
        }
        return $res;
    }

    /*************************************************************************************************************/
    /*                                          PHP deobfuscators                                                */
    /*************************************************************************************************************/

    private function deobfuscateStrrotPregReplaceEval($str, $matches)
    {
        $find = $matches[0];
        $res = str_rot13($matches[2]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200618_1($str, $matches)
    {
        return stripcslashes($str);
    }

    private function deobfuscateBypass($str, $matches)
    {
        $find = $matches[0];
        $bypass = stripcslashes($matches[2]);
        $eval = $matches[3] . $bypass . $matches[4];
        $res = str_replace($find, $eval, $str);
        return $res;
    }

    private function deobfuscateObf_20200720_1($str, $matches)
    {
        $find = $matches[0];
        $res = base64_decode($matches[2]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateGoto($str)
    {
        return Helpers::unwrapGoto($str);
    }

    private function deobfuscateObf_20200527_1($str)
    {
        preg_match('~error_reporting\(0\);define\(\'\w+\',\s*__FILE__\);define\(\'\w+\',\s*fopen\(__FILE__,\s*\'r\'\)\);fseek\(\w+,\s*__COMPILER_HALT_OFFSET__\);((\$\w+="\\\\x[0-9a-f]+";)+(\$\w+="[^"]+";)+eval\("\?>"\.(\$\w+\()+"([^"]+)"\)+;)+(?:/\*\w+\*/)?__halt_compiler\(\);([\w#|>^%\[\.\]\\\\/=]+)~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $encoded = $matches[6];
        $res = preg_replace_callback('~(\$\w+="\\\\x[0-9a-f]+";)+(\$\w+="[^"]+";)+eval\("\?>"\.(\$\w+\()+"([^"]+)"\)+;~msi', static function ($m) use ($str) {
            $layer1 = hex2bin(str_rot13(gzinflate(str_rot13(base64_decode($m[4])))));
            if (preg_match('~(\$\w+="[^"]+";)+eval\(\$\w\.(\$\w+\()+"([^"]+)"\)+;~msi', $layer1, $matches)) {
                $temp = "?>" . hex2bin(str_rot13(gzinflate(str_rot13(base64_decode($matches[3])))));
                while (preg_match('~(\$\w+)=strrev\(\1\);(\1=\s*str_replace\([\'"]([^"\']+)[\'"],"[^"]+",\1\);)+@?eval\("\?\>"\.\$\w+\(\1\)+;~msi', $temp, $matches)) {
                    if (preg_match_all('~(\$\w+)="([^"]+)";~msi', $layer1, $matches1)) {
                        foreach($matches1[1] as $k => $v) {
                            if ($v !== $matches[1]) {
                                continue;
                            }
                            $code = $matches1[2][$k];
                            $code = strrev($code);
                            if (preg_match_all('~str_replace\([\'"]([^"\']+)[\'"],"([^"]+)"~msi', $temp, $m, PREG_SET_ORDER)) {
                                foreach($m as $item) {
                                    $code = str_replace($item[1], $item[2], $code);
                                }
                                $temp = base64_decode($code);
                            }
                            break;
                        }
                    }
                }
                return $temp;
            }
        }, $res);
        if (preg_match_all('~str_replace\([\'"]([^"\']+)[\'"],[\'"]([^"\']+)[\'"]~msi', $res, $m, PREG_SET_ORDER)) {
            foreach($m as $item) {
                $encoded = str_replace($item[1], $item[2], $encoded);
            }
            $res = base64_decode($encoded);
        }

        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200602_1($str)
    {
        preg_match('~(\$\w+)=strrev\("[base64_decode]+"\)\.str_replace\(\'(\w+)\',\'\',\'\w+\'\);\s*eval\(\1\((\$\w+)\)\);~msi', $str, $matches);
        $find = $matches[0];
        $res = 'eval(base64_decode(' . $matches[3] . '));';
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200526_1($str, $matches)
    {
        $find = $matches[0];
        $res = base64_decode($matches[2]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200522_1($str, $matches)
    {
        $find = $matches[0];
        $res = strrev(gzinflate(base64_decode(substr($matches[14], (int)hex2bin($matches[4]) + (int)hex2bin($matches[6]), (int)hex2bin($matches[8])))));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200507_5($str, $matches)
    {
        $find = $matches[0];
        $res = base64_decode($matches[1]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200507_4($str, $matches)
    {
        $find = $matches[0];
        $ar = $matches[2];
        $ar = explode(",\n", $ar);
        $array = [];
        foreach ($ar as $v) {
            $array[substr(trim($v),1,1)] = substr(trim($v), -2, 1);
        }
        unset($ar);
        $res = '';
        $split = str_split($matches[5]);
        foreach ($split as $x) {
            foreach ($array as $main => $val) {
                if ($x == (string)$val) {
                    $res .= $main;
                    break;
                }
            }
        }
        $res = gzinflate(base64_decode($res));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200513_1($str, $matches)
    {
        $find = $matches[0];
        $res = gzuncompress(base64_decode(strrev($matches[5])));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200507_2($str, $matches)
    {
        $find = $matches[0];
        $res = base64_decode($matches[4]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200507_1($str)
    {
        preg_match('~(\$\w+)=base64_decode\(\'([^\']+)\'\);\s*eval\(\1\);~mis', $str, $matches);
        $find = $matches[0];
        $res = base64_decode($matches[2]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200504_1($str)
    {
        preg_match('~(\$\w+)\s*=\s*\("\?>"\.gzuncompress\(base64_decode\("([^"]+)"\)\)\);\s*@?eval\(\1\);~msi', $str, $matches);
        $find = $matches[0];
        $res = ' ?>' . gzuncompress(base64_decode($matches[2]));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateSmartToolsShop($str, $matches)
    {
        $find = $matches[0];
        $res = str_rot13(gzinflate(str_rot13(base64_decode($matches[2]))));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200421_1($str)
    {
        preg_match('~(?:\$\w+\s*=\s*\'\w+\';)?\s*(\$\w+)\s*=\s*urldecode\(\'[%0-9a-f]+\'\);(\s*(\$\w+)\s*=(\s*\1\{\d+\}\.?)+;)+\s*(\$\w+)\s*=\s*"[^"]+"\.\3\("([^"]+)"\);\s*eval\(\5\);~msi', $str, $matches);
        $find = $matches[0];
        $res = ' ?>' . base64_decode($matches[6]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateObf_20200414_1($str, $matches)
    {
        $data = $matches[1];
        $key = $matches[2];
        $res = Helpers::obf20200414_1_decrypt($data, $key);
        return $res;
    }

    private function deobfuscateObf_20200402_2($str, $matches)
    {
        $find = $matches[0];
        $code = $matches[17];
        if (isset($matches[1]) && !empty($matches[1])) {
            $vars = Helpers::collectVars($matches[1], '\'');
            $code = Helpers::replaceVarsFromArray($vars, $matches[2], false, true);
            $code = Helpers::collectStr($code, '\'');
            $code = substr($code, strpos($code,'\'') + 1);
        }
        $code = preg_replace_callback('~\s*"\s*\.((?:min|max|round)?\(\s*\d+[\.\,\|\s\|+\|\-\|\*\|\/]([\d\s\.\,\+\-\*\/]+)?\))\s*\.\s*"~msi', static function($m) {
            return substr(Helpers::calc($m[1]), 1, -1);
        }, $code);
        $res = gzinflate(base64_decode($code)) ?:base64_decode($code);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateTwoHashFunc($str, $matches)
    {
        $funcs = [
            $matches[1].'::'.$matches[2] => [
                'data' => Helpers::prepareArray($matches[3]),
                'func' => null,
            ],
            $matches[4].'::'.$matches[5] => [
                'data' => Helpers::prepareArray($matches[6]),
                'func' => null,
            ],
        ];

        $code = Helpers::normalize($matches[7]);

        foreach ($funcs as $name => &$params){
            $data = $params['data'];
            if (isset($data[0]) && intval($data[0])) {
                $params['func'] = function ($n, $k) use ($data) {
                    if (!isset($data[$n])) {
                        return false;
                    }
                    return $data[$n];
                };
            }
            else {
                $params['func'] = function ($n, $k) use ($data){
                    $l = strlen($k);
                    if (!isset($data[$n])) {
                        return false;
                    }
                    $r = base64_decode($data[$n]);
                    for ($i = 0, $c = strlen($r); $i !== $c;  ++$i) {
                        $r[$i] = chr(ord($r[$i]) ^ ord($k[$i % $l]));
                    }
                    return '\'' . $r . '\'';
                };
            }
        }
        unset($params);

        $new_code = preg_replace_callback('~(_\w{1,5})::(\w{1,5})\s*\(([^)]+)\)~mis', function ($m) use ($funcs) {
            $original       = $m[0];
            $class_name     = $m[1];
            $method_name    = $m[2];
            $vars           = str_replace(['"', "'"], '', $m[3]);

            list($var1, $var2) = explode(',', $vars);
            $func_name = $class_name . '::' . $method_name;
            if (!isset($funcs[$func_name]['func'])) {
                return $original;
            }
            return $funcs[$func_name]['func']($var1, $var2);
        }, $code);
        return MathCalc::calcRawString($new_code);
    }

    private function deobfuscateObf_20200402_1($str, $matches)
    {
        $find = $matches[0];
        $res = gzinflate(hex2bin(pack('H*',$matches[6])));
        $res = preg_replace('~//.+$~m', '', $res);
        preg_match('~\$\w+\(\$\w+,\$\w+\("",\s*\$\w+\(\$\w+\(\$\w+\(\$\w+\(\$\w+,\s*"(\d+)"\)+,\$\w+\);.+function \w+\((\$\w+),\s*\$\w+,\s(\$\w+)\)\s{\3\s=\s\3\s\.\s\3;.+return \2;}~msi', $res, $matches);
        $res = gzinflate(hex2bin(pack('H*',$matches[1])));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateOELove($str)
    {
        preg_match('~<\?php\s*defined\(\'[^\']+\'\)\s*\|\|\s*define\(\'[^\']+\',__FILE__\);(global\s*\$[^;]+;)+\s*(if\(!function_exists\(\'([^\']+)\'\)\){\s*function\s*[^\)]+\(\$[^,]+,\$[^=]+=\'\'\){\s*if\(empty\(\$[^\)]+\)\)\s*return\s*\'\';\s*\$[^=]+=base64_decode\(\$[^\)]+\);\s*if\(\$[^=]+==\'\'\)\s*return\s*\~\$[^;]+;\s*if\(\$[^=]+==\'-1\'\)\s*@[^\(]+\(\);\s*\$[^=]+=\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\(\$[^\)]+\);\s*\$[^=]+=\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\(\$[^,]+,\$[^,]+,\$[^\)]+\);\s*return\s*\$[^^]+\^\$[^;]+;\s*}}\s*)+(\$[^\[]+\["[^"]+"]=[^\(]+\(\'[^\']+\',\'[^\']*\'\);\s*)+(\$[^\[]+\[\'[^\']+\'\]=\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\([^\)]*\)+;\s*)+return\(eval\(\$[^\[]+\[\'[^\']+\'\]\)+;\s*\?>\s*#!/usr/bin/php\s*-q\s*((\s*[^\s]+)+)~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $code = $matches[6];
        $res = iconv('UTF-8', 'ASCII//IGNORE', $res);

        preg_match('~\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\(\'([\da-f]{32})\'\);~msi', $res, $hash);
        $hash = strrev($hash[1]);
        preg_match_all('~\$GLOBALS\[\'[^\']+\'\]\[\'[^\']+\'\]\(\'([\d]{10})\'\)~msi', $res, $substr_offsets);
        $substr_offsets = $substr_offsets[1];
        $substr_offsets = array_map('strrev', $substr_offsets);
        $substr_offsets = array_map('intval', $substr_offsets);

        preg_match_all('~if\s*\(\!function_exists\(\'([^\']+)\'\)~msi', $res, $decoders);
        $decoders = $decoders[1];
        $var_array = [];
        preg_match_all('~\$([^\[]{3,20})\["([^"]+)"\]=(\w+)\(\'([^\']*)\',\'([^\']*)\'\);~msi', $res, $vars, PREG_SET_ORDER);
        $var_name = $vars[0][1];
        foreach ($vars as $var) {
            if ($var[3] === $decoders[0] || $var[3] === $decoders[1]) {
                $var_array[$var[2]] = Helpers::OELoveDecoder($var[4], $var[5]);
                $res = str_replace($var[0], '', $res);
            }
        }
        $layer1 = substr($code, 0, $substr_offsets[3] + 96);
        $layer1_dec = iconv('UTF-8', 'ASCII//IGNORE', gzuncompress(base64_decode($layer1)));
        $code = str_replace($layer1, $layer1_dec, $code);
        preg_match_all('~\$([^\[]{3,20})\["([^"]+)"\]=(\w+)\(\'([^\']*)\',\'([^\']*)\'\);~msi', $code, $vars, PREG_SET_ORDER);
        foreach ($vars as $var) {
            if ($var[3] === $decoders[0] || $var[3] === $decoders[1]) {
                $var_array[$var[2]] = Helpers::OELoveDecoder($var[4], $var[5]);
                $code = str_replace($var[0], '', $code);
            }
        }
        $layer2_start = strpos($code, '?>') + 2;
        $layer2 = substr($code, $layer2_start + $substr_offsets[2]);
        $layer2_dec = iconv('UTF-8', 'ASCII//IGNORE', gzuncompress(base64_decode(str_rot13($layer2))));
        $res = $layer2_dec;
        foreach($var_array as $k => $v) {
            $res = str_replace('$GLOBALS[\'' . $var_name . '\'][\'' . $k . '\'](', $v . '(', $res);
            $res = str_replace('$GLOBALS[\'' . $var_name . '\'][\'' . $k . '\']', '\'' . $v . '\'', $res);
        }

        $res = preg_replace_callback('~(\w+)\(\'([^\']*)\',\'([^\']*)\'\)~msi', static function ($m) use ($decoders) {
            if ($m[1] !== $decoders[0] && $m[1] !== $decoders[1]) {
                return $m[0];
            }
            return '\'' . Helpers::OELoveDecoder($m[2], $m[3]) . '\'';
        }, $res);

        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalConcatVars($str)
    {
        preg_match('~((\$\w+="";\$\w+\s*\.=\s*"[^;]+;\s*)+)(?:(?:\$\w+)="";)?(eval\((\s*(\$\w+)\s*\.)+\s*"([^"]+)(?:"\);)+)~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $parts = [];
        preg_match_all('~(\$\w+)="";\1\s*\.=\s*"([^"]+)"~msi', $matches[1], $matches1, PREG_SET_ORDER);
        foreach($matches1 as $match) {
            $parts[$match[1]] = stripcslashes(stripcslashes($match[2]));
        }
        $res = stripcslashes(stripcslashes($matches[3]));
        foreach($parts as $k => $v) {
            $res = str_replace($k, "'" . $v . "'", $res);
        }
        $res = preg_replace_callback('/[\'"]\s*?\.+\s*?[\'"]/smi', static function($m) {
            return '';
        }, $res);

        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalAssignedVars($str, $matches)
    {
        $res = $str;

        $vars = [$matches[1] => $matches[2]];

        $res = preg_replace_callback('~(\$\w{1,3000})=(base64_decode|gzinflate|convert_uudecode|str_rot13)\((\$\w{1,3000})\);~msi',
            function ($match) use (&$vars) {
                $func = $match[2];
                if (Helpers::convertToSafeFunc($func) && isset($vars[$match[3]])) {
                    $vars[$match[1]] = @$func($vars[$match[3]]);
                    return '';
                }
                return $match[1] . '=' . $match[2] . '(\'' . $match[3] . '\';';
            }, $res);

        $res = $vars[$matches[4]] ?? Helpers::replaceVarsFromArray($vars, $res);

        return $res;
    }

    private function deobfuscateVarFuncsEval($str)
    {
        preg_match('~((\$\w+)\s*=\s*)(base64_decode\s*\(+|gzinflate\s*\(+|strrev\s*\(+|str_rot13\s*\(+|gzuncompress\s*\(+|convert_uudecode\s*\(+|urldecode\s*\(+|rawurldecode\s*\(+|htmlspecialchars_decode\s*\(+)+"([^"]+)"\)+(;\s*@?eval\(([\'"?>.\s]+)?\2\);)~', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $res = str_replace([$matches[5], $matches[1]], [');', 'eval('], $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateComments($str, $matches)
    {
        $find = $matches[0];
        $res = preg_replace('~/\*\w+\*/~msi', '', $str);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateStrrevVarEval($str)
    {
        preg_match('~(\$\w+=strrev\("[^"]+"\);)+eval\((\$\w+\()+"([^"]+)"\)+;~mis', $str, $matches);
        $find = $matches[0];
        $res = gzinflate(base64_decode($matches[3]));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateAanKFM($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        $key = Helpers::aanKFMDigitsDecode($matches[3]);
        $res = Helpers::Xtea_decrypt($matches[4], $key);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalChars($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        while(preg_match_all('~(?:@eval((?:\(\$[0O]+\[[\'"]\w+[\'"]\])+)\("([^"]+)"\)+;)|("\)\?\$[O0]+)~msi', $res, $matches, PREG_SET_ORDER)) {
            $match = $matches[0];
            if (isset($matches[1])) $match = $matches[1];
            $count = ($match[1] !== '') ? substr_count($match[1], '(') : 0;
            if ($count == 2) {
                $res = gzinflate(base64_decode($match[2]));
            } else if ($count == 3) {
                $res = gzinflate(base64_decode(str_rot13($match[2])));
            }
            if (isset($match[3]) && ($match[3] !== '')) {
                $res = preg_replace_callback('~(\$[0O]+\["\w+"\]\()+"([^"]+)"\)+;?~msi', static function($m) {
                    return gzinflate(base64_decode(str_rot13($m[2])));
                }, $res);
            }
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateGlobalsBase64($str)
    {
        preg_match('~<\?php\s+((\$GLOBALS\[\s*[\'"]\w+[\'"]\s*\])\s*=\s*base64_decode\("([^"]*)"\);)+\s*\?>(<\?php\s.+\2.+exit;\s}\sfunction\s\w+\(\)\s{\sreturn\sarray\(\s\'favicon\'\s=>\s\'[^\']+\',\s+\'sprites\'\s=>\s\'[^\']+\',\s\);\s})~msi', $str, $matches);
        $find = $matches[0];
        $vars = [];
        preg_match_all('~(\$GLOBALS\[\s*[\'"]\w+[\'"]\s*\])\s*=\s*base64_decode\("([^"]*)"\);~msi', $matches[0], $matches1, PREG_SET_ORDER);
        foreach($matches1 as $match) {
            $vars[$match[1]] = base64_decode($match[2]);
        }
        $code = $matches[4];
        foreach ($vars as $var => $value) {
            $code = str_replace($var . '(', $value . '(', $code);
            $code = str_replace($var, "'" . $value . "'", $code);
        }
        $res = $code;
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalReturn($str, $matches)
    {
        $find = $matches[0];
        $res = stripcslashes(base64_decode($matches[2]));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateQibosoft($str)
    {
        preg_match('~\$\w+=__FILE__;\$\w+=fopen\(\$\w+,\'rb\'\);fread\(\$\w+,(\d+)\);\$\w+=explode\("\\\\t",base64_decode\(fread\(\$\w+,(\d+)\)+;\$\w+=\$\w+\[[\d+]\];[\$l1=\d{}\.;\(\)\[\]]+eval\(\$\w+\(\'([^\']+)\'\)+;\s*return\s*;\?>[\w=\+]+~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $hangs = 15;
        $obfPHP = explode('?>', $str);
        $obfPHP = $obfPHP[1];
        preg_match('~eval\(\$\w+\(\'([^\']+)\'\)+;~msi', $res, $temp);
        $res = str_replace($temp[0], base64_decode($temp[1]), $res);
        $offset = $matches[2];
        while (preg_match('~\$\w+\(\$\w+,(\d+)\);\s*eval\(\$\w+\(\$\w+\(\$\w+,(\d+)\)+;~msi', $res, $temp2) && $hangs--) {
            $offset += $temp2[1];
            $decode_loop = base64_decode(substr($obfPHP, $offset, $temp2[2]));
            $offset += $temp2[2];
            if (preg_match('~eval\(\$\w+\(\'([^\']+)\'\)+;~msi', $decode_loop, $temp)) {
                $res = str_replace($temp2[0], base64_decode($temp[1]), $res);
            } else {
                $res = $decode_loop;
            }

        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateUd64($str)
    {
        preg_match('~(\$ud64_c[o0]m="[\\\\0-9a-z\."]+;)+\$\w+=(\$ud64_c[o0]m\()+"([^"]+)"\)+;@eval\(\$ud64_c[o0]m\(\'[^\']+\'\)+;~msi', $str, $matches);
        $find = $matches[0];
        $res = gzinflate(convert_uudecode(base64_decode(gzinflate(base64_decode(str_rot13($matches[3]))))));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateCustom1($str)
    {
        preg_match('~\$\w+="([^"]+)";\$l+=0;\$l+=\'base64_decode\';\$l+=0;eval\(.+?;eval\(\$l+\);return;~msi', $str, $matches);
        return Helpers::someDecoder3($matches[1]);
    }

    private function deobfuscateCustom2($str, $matches)
    {
        $find = $matches[0];
        $key = $matches[2];
        $var = $matches[3];
        preg_match_all('~(\$\w+)\[\d+\]\s*=\s*"([^"]+)";~msi', $str, $matches);
        foreach ($matches[1] as $k => &$m) {
            if ($m !== $var) {
                unset($matches[2][$k]);
            }
        }
        $res = base64_decode(Helpers::someDecoder4($matches[2], $key));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateLockIt2($str, $matches)
    {
        $find = $matches[0];
        $res = $matches[1];

        if(strpos($str, '$_X="') !== false && strpos($res, '\\x') !== false) {
            $res = stripcslashes($res);
        }
        if (preg_match_all('~\$[_\w]+\.=[\'"]([\w\+\/=]+)[\'"];~', $matches[0], $concatVars)) {
            foreach ($concatVars[1] as $concatVar) {
                $res .= $concatVar;
            }
        }
        $res = base64_decode($res);
        $res = strtr($res, $matches[2], $matches[3]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateAnaski($str, $matches)
    {
        $find = $matches[0];

        $res = gzinflate(str_rot13(base64_decode($matches[2])));
        $res = strtr($res, $matches[5], $matches[6]);

        return $res;
    }

    private function deobfuscateFuncs($str, $matches)
    {
        $find = $matches[0];
        $funcs = [];
        $payload = $matches[7];
        $var = $matches[6];
        $res = str_replace($matches[8], stripcslashes($matches[9]), $str);
        $res = preg_replace_callback('~function\s*(\w+)\((\$\w+)\){\s*return\s*(\w+)\(\2(,\d+)?\);}\s*~msi', static function($matches2) use (&$funcs){
            $funcs[$matches2[1]] = $matches2[3];
            return '';
        }, $res);
        foreach ($funcs as $k => $v) {
            $res = str_replace($k . '(', $v . '(', $res);
        }
        $res = str_replace([$var . '="' . $payload . '";', $var], ['', '"' . $payload . '"'], $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateSubstr($str)
    {
        preg_match('~\$\w+=0;(\$GLOBALS\[\'\w+\'\])\s*=\s*\'([^\']+)\';\s*(\$\w+)=pack\(\'H\*\',substr\(\1,\s*([-\d]+)\)\);if\s*\(!function_exists\(\'(\w+)\'\)\){function\s*\5\(\$\w+,\s*\$\w+\){\$\w+=\1;\s*\$d=pack\(\'H\*\',substr\(\1,\s*\4\)\);\s*return\s*\$\w+\(substr\(\$\w+,\s*\$\w+,\s*\$\w+\)\);}};eval\(\3\(\'([^\']+)\'\)\);~msi', $str, $matches);
        $find = $matches[0];
        $substr_array = $matches[2];
        $offset = intval($matches[4]);
        $func = $matches[5];
        $eval = pack('H*',substr($substr_array, $offset));
        $res = Helpers::convertToSafeFunc($eval) ? @$eval($matches[6]) : $matches[6];
        $res = preg_replace_callback('~(\w+)\(([-\d]+),\s*([-\d]+)\)~mis', static function ($matches) use ($eval, $substr_array, $func) {
            if ($matches[1] !== $func) {
                return $matches[0];
            }
            $res = Helpers::convertToSafeFunc($eval) ? @$eval(substr($substr_array, $matches[2], $matches[3])) : $matches[0];
            return '\'' . $res . '\'';
        }, $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscatePHPJiaMi($str, $matches)
    {
        $find = $matches[0];
        $bin = bin2hex($str);
        preg_match('~6257513127293b24[a-z0-9]{2,30}3d24[a-z0-9]{2,30}2827([a-z0-9]{2,30})27293b~', $bin, $hash);
        preg_match('~2827([a-z0-9]{2})27293a24~', $bin, $rand);
        $hash = hex2bin($hash[1]);
        $rand = hex2bin($rand[1]);
        $res = Helpers::PHPJiaMi_decoder(substr($matches[3], 0, -45), $hash, $rand);
        $res = str_rot13(@gzuncompress($res) ?: $res);

        if (preg_match('~global\s*(\$[^,;]+);((?:\1\[\'[^\']+\'\]=[^(]+\(\'[^\']+\'\);)+)~msi', $str, $tmp))
        {
            $tmp = explode(';', $tmp[2]);
            foreach ($tmp as $entry) {
                if ($entry === '') {
                    continue;
                }
                preg_match('~\$([^\[]+)(\[\'[^\']+\'\])=([^\(]+)\(\'([^\']+)\'\)~', $entry, $parts);
                $res = str_replace('$GLOBALS[\'' . $parts[1] . '\']' . $parts[2], Helpers::PHPJiaMi_decoder($parts[4], $hash, $rand), $res);
            }
            $func_decrypt = $parts[3];
            $hangs = 20;
            while (($start = strpos($res, $func_decrypt . '(\'')) && $start !== false && $hangs--) {
                $end = strpos($res,'\'', $start + strlen($func_decrypt) + 2) + 1;
                $data = substr($res, $start + strlen($func_decrypt) + 2, $end - ($start + strlen($func_decrypt) + 2 + 1));
                $res = substr_replace($res, '\'' . Helpers::PHPJiaMi_decoder($data, $hash, $rand) . '\'', $start, ($end - $start) + 1);
            }
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalIReplace($str, $matches)
    {
        $find = $matches[0];
        $res = base64_decode($matches[3]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateErrorHandler($str)
    {
        preg_match('~(\$\w+)="[^"]+";\s*(\$\w+)=str_ireplace\("[^"]+","",\1\);(\$\w+)\s*=\s*"([^"]+)";\s*function\s*(\w+)\((\$\w+,?)+\){\s*(\$\w+)=\s*create_function\(\'\',\$\w+\);\s*array_map\(\7,array\(\'\'\)+;\s*}\s*set_error_handler\(\'\5\'\);(\$\w+)=\2\(\3\);user_error\(\8,E_USER_ERROR\);\s*if\s*.+?}~msi', $str, $matches);
        $find = $matches[0];
        $res = base64_decode($matches[4]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateStrtoupper($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        $alph = $matches[2];
        $var = $matches[1];
        $res = str_replace("{$var}=\"{$alph}\";", '', $res);
        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace($var . '[' . $i . '].', "'" . $alph[$i] . "'", $res);
            $res = str_replace($var . '[' . $i . ']', "'" . $alph[$i] . "'", $res);
        }
        $res = str_replace("''", '', $res);
        $res = str_replace("' . '", '', $res);
        $res = str_replace("' '", '', $res);
        preg_match('~(\$\w+)\s*=\s*strtoupper\s*\(\s*\'(\w+)\'\s*\)\s*;~msi', $res, $matches);
        $matches[2] = strtoupper($matches[2]);
        $res = str_replace($matches[0], '', $res);
        $res = preg_replace_callback('~\${\s*(\$\w+)\s*}~msi', static function ($m) use ($matches) {
            if ($m[1] !== $matches[1]) {
                return $m[0];
            }
            return '$' . $matches[2];
        }, $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEval2($str)
    {
        preg_match('~(\$\w+)\s*=\s*"((?:[^"]|(?<=\\\\)")*)";(\$\w+)\s*=\s*(\1\[\d+\]\.?)+;(\$\w+)\s*=\s*[^;]+;(\$\w+)\s*=\s*"[^"]+";\$\w+\s*=\s*\5\."([^"]+)"\.\6;\3\((\1\[\d+\]\.?)+,\s*\$\w+\s*,"\d+"\);~smi', $str, $matches);
        $res = $str;
        list($find, $var, $alph) = $matches;
        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace($var . '[' . $i . '].', "'" . $alph[$i] . "'", $res);
            $res = str_replace($var . '[' . $i . ']', "'" . $alph[$i] . "'", $res);
        }
        $res = gzinflate(base64_decode(substr($matches[7], 1, -1)));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalEregReplace($str, $matches)
    {
        $find = $matches[0];
        $res = base64_decode($matches[2]);
        preg_match_all('~(\$\w+)\s*=\s*ereg_replace\("([^"]+)","([^"]+)",\1\);~smi', $str, $matches);
        foreach ($matches[2] as &$pat) {
            if ($pat[0] === '[') {
                $pat = substr($pat, 1, -1);
            }
        }
        unset($pat);
        $res = str_replace($matches[2], $matches[3], $res);
        $res = base64_decode($res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateStrreplace($str, $matches)
    {
        $find = $matches[0];
        $res = $str;

        $str_replace = '';
        $base64_decode = '';
        $layer = '';

        if (!preg_match_all('~(?:(\$\w{1,50})\s?=\s?((?:\'[^\']{1,500}\'|"[^\n]{1,500}?"));[\n\s])~msi', $str, $matches, PREG_SET_ORDER)) {
            preg_match_all('~(\$\w+)\s*=\s*([\'"](?|[^\']+\'|[^"]+"));~msi', $str, $matches, PREG_SET_ORDER);
        }
        foreach ($matches as $i => $match) {
            $vars[$match[1]] = substr($match[2], 1, -1);
        }

        $res = preg_replace_callback('~(\$\w+)\s*=\s*str_replace\([\'"](\w+)[\'"],\s*[\'"]{2},\s*[\'"](\w+)[\'"]\)~msi',
            static function ($matches) use (&$vars, &$str_replace) {
                $vars[$matches[1]] = str_replace($matches[2], "", $matches[3]);
                if ($vars[$matches[1]] === 'str_replace') {
                    $str_replace = $matches[1];
                }
                return $matches[1] . ' = "' . $vars[$matches[1]] . '"';
            }, $res);

        if ($str_replace !== '') {
            $res = preg_replace_callback('~(\$\w+)\s*=\s*(\$\w+)\("(\w+)",\s*"",\s*"(\w+)"\)~msi',
                static function ($matches) use (&$vars, &$base64_decode, $str_replace) {
                    if ($matches[2] !== $str_replace) {
                        return $matches[0];
                    }
                    $vars[$matches[1]] = str_replace($matches[3], "", $matches[4]);
                    if ($vars[$matches[1]] === 'base64_decode') {
                        $base64_decode = $matches[1];
                    }
                    return $matches[1] . ' = "' . $vars[$matches[1]] . '"';
                }, $res);

            $res = preg_replace_callback('~(\$\w+)\((\$\w+)\("(\w+)",\s*"",\s*([\$\w\.]+)\)~msi',
                static function ($matches) use (&$vars, &$layer, $base64_decode, $str_replace) {
                    if ($matches[1] !== $base64_decode && $matches[2] !== $str_replace) {
                        return $matches[0];
                    }
                    $tmp = explode('.', $matches[4]);
                    foreach ($tmp as &$item) {
                        $item = $vars[$item];
                    }
                    unset($item);
                    $tmp = implode('', $tmp);
                    $layer = base64_decode(str_replace($matches[1], "", $tmp));

                    return $matches[0];
                }, $res);
        }

        if ($base64_decode !== '') {
            $regex = '~(\$\w+)\((\$\w+)\("(\w+)",\s*"",\s*([\$\w\.]+)\)~msi';
        } else {
            $regex = '~(str_replace)\(([\'"])([^\'"]+)[\'"],\s*[\'"]{2},\s*([\$\w\. ]+)\);\s?(\$\w+)\s*=\s*\$\w+\([\'"]{2},\s*\$\w+\);\s*\5\(\);~msi';
        }
        preg_replace_callback($regex,
            static function ($matches) use (&$vars, &$layer, $base64_decode, $str_replace) {
                if ($base64_decode !== '' && $matches[1] !== $base64_decode && $matches[2] !== $str_replace) {
                    return $matches[0];
                }
                $tmp = preg_split('~\s*\.\s*~msi', $matches[4]);

                foreach ($tmp as &$item) {
                    $item = $vars[$item];
                }
                unset($item);
                $tmp = implode('', $tmp);
                $layer = str_replace($matches[3], "", $tmp);
                if ($base64_decode !== '') {
                    $layer = base64_decode($layer);
                }
                return $matches[0];
            }, $res);
        $res = str_replace($find, $layer, $str);
        return $res;
    }

    private function deobfuscateSeolyzer($str, $matches)
    {
        $find           = $matches[0];
        $res            = $str;
        $vars           = [];
        $base64_decode  = '';
        $layer          = '';
        $gzuncompress   = '';

        preg_match_all('~(\$\w+)\s*=\s*([^$][^;]+)\s*;~msi', $str, $matches, PREG_SET_ORDER);
        foreach ($matches as $i => $match) {
            $var_name   = $match[1];
            $var_val    = trim($match[2]);
            if (preg_match('~"[^"]{0,20}"\s*\.chr\s*\(~i', $var_val)) {
                $var_val = Helpers::normalize($var_val);
            }
            $var_val = preg_replace('~^["\'](.*)["\']$~i', '\1', $var_val);
            $vars[$var_name] = trim($var_val);
            if ($var_val === 'base64_decode') {
                $base64_decode = $var_name;
            }
        }

        $res = preg_replace_callback('~\s*=\s*(\$\w+)\((\$\w+)\)~msi', static function ($matches) use (&$vars, &$gzuncompress, &$layer, $base64_decode) {
            if ($matches[1] !== $base64_decode) {
                return $matches[0];
            }
            if (!isset($vars[$matches[2]])) {
                return $matches[2];
            }
            $tmp = base64_decode($vars[$matches[2]]);
            if ($tmp === 'gzuncompress') {
                $gzuncompress = $matches[2];
            }
            $vars[$matches[2]] = $tmp;
            return " = '{$tmp}'";
        }, $res);

        if ($gzuncompress !== '') {
            $res = preg_replace_callback('~(\$\w+)\(\s*(\$\w+)\((\$\w+)\)~msi',
                function ($matches) use (&$vars, $gzuncompress, &$layer, $base64_decode) {
                    if ($matches[1] !== $gzuncompress && $matches[2] !== $base64_decode) {
                        return $matches[0];
                    }
                    if (!isset($vars[$matches[3]])) {
                        return $matches[3];
                    }
                    $tmp = gzuncompress(base64_decode($vars[$matches[3]]));
                    $layer = $matches[3];
                    $vars[$matches[3]] = $tmp;
                    return "'{$tmp}'";
                }, $res);
            $res = $vars[$layer];
        } else if (preg_match('~\$\w+\(\s*(\$\w+)\((\$\w+)\)~msi', $res)) {
            $res = preg_replace_callback('~\$\w+\(\s*(\$\w+)\((\$\w+)\)~msi',
                function ($matches) use (&$vars, &$layer, $base64_decode) {
                    if ($matches[1] !== $base64_decode) {
                        return $matches[0];
                    }
                    if (!isset($vars[$matches[2]])) {
                        return $matches[2];
                    }
                    $tmp = base64_decode($vars[$matches[2]]);
                    $layer = $matches[2];
                    $vars[$matches[2]] = $tmp;
                    return "'{$tmp}'";
                }, $res);
            $res = $vars[$layer];
        }
        return str_replace($find, $res, $str);
    }

    private function deobfuscateCreateFunc($str, $matches)
    {
        $result = $str;
        $funcs = str_replace($matches[4], '', $matches[3]);

        if (Helpers::concatStr($matches[1]) === 'create_function'
            && Helpers::concatStr($matches[2]) === 'eval') {
            $funcs = explode('(', $funcs);
            $iMax = count($funcs) - 2;
            $final_code = $matches[5];

            for ($i = $iMax; $i >= 0; $i--) {
                if ($funcs[$i][0] !== '\'' && $funcs[$i][0] !== '"') {
                    $funcs[$i] = '\'' . $funcs[$i];
                }
                $func = Helpers::concatStr($funcs[$i] . '"');
                if (Helpers::convertToSafeFunc($func)) {
                    $final_code = @$func($final_code);
                }
            }
            $result = $final_code;
        }
        $result = ' ?>' . $result;

        return $result;
    }

    private function deobfuscateGotoShell($str, $matches)
    {
        $str = Helpers::normalize($str);

        $str = preg_replace('~\${\'GLOBALS\'}\[\'(\w+)\'\]~msi', '$\1', $str);

        $vars = Helpers::collectVars($str, '\'');
        $need_remove_vars = [];
        foreach ($vars as $name => $value) {
            $last_str = $str;
            $str = str_replace('${' . $name . '}', '$' . $value, $str);
            if ($last_str != $str) {
                $need_remove_vars[$name] = $value;
            }
        }

        foreach ($need_remove_vars as $name => $value) {
            if (substr_count($str, $name) != 1) {
                continue;
            }
            $str = str_replace($name.'=\'' . $value . '\';', '', $str);
        }
        return $str;
    }

    private function deobfuscateCreateFuncConcat($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        $vars = [];
        $res = preg_replace_callback('~(?|(\$\w+)\s*=\s*(([base64_decode\'\.\s]+)|([eval\'\.\s]+)|([create_function\'\.\s]+)|([stripslashes\'\.\s]+)|([gzinflate\'\.\s]+)|([strrev\'\.\s]+)|([str_rot13\'\.\s]+)|([gzuncompress\'\.\s]+)|([urldecode\'\.\s]+)([rawurldecode\'\.\s]+));)~', static function($matches) use (&$vars) {
            $tmp = str_replace('\' . \'', '', $matches[0]);
            $tmp = str_replace('\'.\'', '', $tmp);
            $value = str_replace('\' . \'', '', $matches[2]);
            $value = str_replace('\'.\'', '', $value);
            $vars[$matches[1]] = substr($value, 1, -1);
            return $tmp;
        }, $res);
        foreach($vars as $key => $var) {
            $res = str_replace($key, $var, $res);
            $res = str_replace($var . ' = \'' . $var . '\';', '', $res);
            $res = str_replace($var . ' = "";', '', $res);
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalWrapVar($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        $vars = [];
        $res = preg_replace_callback('~(?|(\$\w+)\s*=\s*(([base64_decode"\'\.\s]+)|([eval"\'\.\s]+)|([create_function"\'\.\s]+)|([stripslashes"\'\.\s]+)|([gzinflate"\'\.\s]+)|([strrev"\'\.\s]+)|([str_rot13"\'\.\s]+)|([gzuncompress"\'\.\s]+)|([urldecode"\'\.\s]+)([rawurldecode"\'\.\s]+));)~msi', static function($matches) use (&$vars) {
            $tmp = preg_replace('~[\'"]\s*?[\+\.]+\s*?[\'"]~msi', '', $matches[0]);
            $value = preg_replace('~[\'"]\s*?[\+\.]+\s*?[\'"]~msi', '', $matches[2]);
            $vars[$matches[1]] = substr($value, 1, -1);
            return $tmp;
        }, $res);
        $res = preg_replace_callback('~\("([^\)]+)\'\)~msi',  function ($m) {
            return '(\'' . preg_replace('~[\'"]\s*?[\+\.]+\s*?[\'"]~msi', '', $m[1]) . '\'\)';
        }, $res);
        $temp = substr($res, strpos($res, '@eval'));
        $before = substr($res, 0, strpos($res, '@eval'));
        $temp1 = $temp;
        foreach($vars as $key => $var) {
            $temp = str_replace($key, $var, $temp);
        }
        $res = str_replace($temp1, $temp, $res);
        $res = str_replace($find, $res, $str);
        $res = $this->deobfuscateEval($res, []);
        $res = preg_replace('~/\*[^\*]+\*/~msi', '', $res);
        return $before . $res;
    }

    private function deobfuscateForEach($str, $matches)
    {
        $find = $matches[0];
        $alph = $matches[3];
        $vars = [];
        $res = $str;

        preg_replace('~\s*/\*\w+\*/\s*~msi', '', $res);

        $res = preg_replace_callback('~foreach\(\[([\d,]+)\]\s*as\s*\$\w+\)\s*\{\s*(\$\w+)\s*\.=\s*\$\w+\[\$\w+\];\s*\}~mis', static function($matches) use ($alph, &$vars) {
            $chars = explode(',', $matches[1]);
            $value = '';
            foreach ($chars as $char) {
                $value .= $alph[$char];
            }
            $vars[$matches[2]] = $value;
            return "{$matches[2]} = '{$value}';";
        }, $res);

        foreach($vars as $key => $var) {
            $res = str_replace($key, $var, $res);
            $res = str_replace($var . " = '" . $var . "';", '', $res);
            $res = str_replace($var . ' = "";', '', $res);
        }

        preg_match('~(\$\w+)\s*=\s*strrev\([create_function\.\']+\);~ms', $res, $matches);
        $res = str_replace($matches[0], '', $res);
        $res = str_replace($matches[1], 'create_function', $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateSubst2($str)
    {
        preg_match('~(\$\w+)="([^"])+(.{0,70}\1.{0,400})+;\s*}~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        preg_match('~(\$\w+)="(.+?)";~msi', $str, $matches);
        $alph = stripcslashes($matches[2]);
        $var = $matches[1];
        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace($var . '[' . $i . '].', "'" . $alph[$i] . "'", $res);
            $res = str_replace($var . '[' . $i . ']', "'" . $alph[$i] . "'", $res);
        }
        $res = str_replace("''", '', $res);
        preg_match_all('~(\$GLOBALS\[\'\w{1,40}\'\])\s*=\s*\'(([^\'\\\\]++|\\\\.)*)\';~msi', $res, $matches, PREG_SET_ORDER);

        foreach ($matches as $index => $var) {
            $res = str_replace($var[1], $var[2], $res);
            $res = str_replace($var[2] . " = '" . $var[2] . "';", '', $res);
        }

        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateAssert($str, $matches)
    {
        $find = $matches[0];
        $res = base64_decode($matches[3]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateUrlDecode2($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        if (isset($matches[10])) {
            $res = base64_decode($matches[10]);
        }
        if (preg_match('~\$\w+=["\']([^\'"]+)[\'"];\s*eval\(\'\?>\'\.[\$\w\(\)\*,\s]+;~msi', $res, $match)) {
            $res = base64_decode(strtr(substr($match[1], 52*2), substr($match[1], 52, 52), substr($match[1], 0, 52)));
        }

        if (preg_match('~function\s*(\w+)\(\$\w+\)[\w{\$=\s*();<+\[\]\-]+\}\s+return[\$\s\w;]+}eval\(\1\("([\w\/+=]+)?"\)\);~', $res, $matchEval)) {
            $res = gzinflate(base64_decode($matchEval[2]));
            for ($i=0, $iMax = strlen($res); $i < $iMax; $i++) {
                $res[$i] = chr(ord($res[$i])-1);
            }
            $res = str_replace($find, $res, $str);
            return $res;
        }

        if (preg_match('~header\(\'[^\']+\'\);(?:\$\w+=\${[^}]+}\[[^\]]+\]\(\'.*?\'?;}?\'\);)+\${[^}]+}\[[^\]]+\]\(\);~msi',
            $matches[6], $match)) {
            $res = stripcslashes($match[0]);
            $dictionaryValue = urldecode($matches[3]);
            $vars = Helpers::getVarsFromDictionary($dictionaryValue, $str);
            $res = Helpers::replaceVarsFromArray($vars, $res);
            $res = Helpers::replaceCreateFunction($res);

            preg_match('~\$([0_O]+)\s*=\s*function\s*\((\$\w+)\)\s*\{\s*\$[O_0]+\s*=\s*substr\s*\(\2,(\d+),(\d+)\);\s*\$[O_0]+\s*=\s*substr\s*\(\2,([\d-]+)\);\s*\$[O_0]+\s*=\s*substr\s*\(\2,(\d+),strlen\s*\(\2\)-(\d+)\);\s*return\s*gzinflate\s*\(base64_decode\s*\(\$[O_0]+\s*\.\s*\$[O_0]+\s*\.\s*\$[O_0]+\)+;~msi', $res, $m);
            $res = preg_replace_callback('~\$\{"GLOBALS"}\["([0_O]+)"\]\s*\(\'([^\']+)\'\)~msi', static function ($calls) use ($m) {
                if ($calls[1] !== $m[1]) {
                    return $calls[0];
                }
                $temp1 = substr($calls[2], $m[3], $m[4]);
                $temp2 = substr($calls[2], $m[5]);
                $temp3 = substr($calls[2], $m[6],strlen($calls[2]) - $m[7]);
                return "'" . gzinflate(base64_decode($temp1 . $temp3 . $temp2)) . "'";
            }, $res);
            return $res;
        }


        $res = str_replace($find, ' ?>' . $res, $str);
        return $res;
    }

    private function deobfuscatePHPMyLicense($str)
    {
        preg_match('~\$\w+\s*=\s*base64_decode\s*\([\'"][^\'"]+[\'"]\);\s*if\s*\(!function_exists\s*\("rotencode"\)\).{0,1000}eval\s*\(\$\w+\s*\(base64_decode\s*\([\'"]([^"\']+)[\'"]\)+;~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $hang = 10;
        while(preg_match('~eval\s*\(\$\w+\s*\(base64_decode\s*\([\'"]([^"\']+)[\'"]\)+;~msi', $res, $matches) && $hang--) {
            $res = gzinflate(base64_decode($matches[1]));
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEdoced_46esab($str)
    {
        preg_match('~(\$\w+)=[\'"]([^"\']+)[\'"];(\$\w+)=strrev\(\'edoced_46esab\'\);eval\(\3\([\'"]([^\'"]+)[\'"]\)+;~msi', $str, $matches);
        $find = $matches[0];
        $res = '';
        $decoder = base64_decode($matches[4]);
        preg_match('~(\$\w+)=base64_decode\(\$\w+\);\1=strtr\(\1,[\'"]([^\'"]+)[\'"],[\'"]([^\'"]+)[\'"]\);~msi', $decoder, $matches2);
        $res = base64_decode($matches[2]);
        $res = strtr($res, $matches2[2], $matches2[3]);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEdoced_46esab_etalfnizg($str, $matches)
    {
        return gzinflate(base64_decode($matches[3]));
    }

    private function deobfuscateEvalVarVar($str)
    {
        preg_match('~\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\'](\w+)[\'"];\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\]=["\']\2[\'"];(\${\$\{"GLOBALS"\}\[[\'"]\3[\'"]\]})=[\'"]([^\'"]+)[\'"];eval.{10,50}?(\$\{\$\{"GLOBALS"\}\[[\'"]\1[\'"]\]\})\)+;~msi', $str, $matches);
        $find = $matches[0];
        $res = str_replace($matches[4], '$' . $matches[2], $str);
        $res = str_replace($matches[6], '$' . $matches[2], $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEscapes($str, $matches)
    {
        $find = $matches[0];
        $res = stripcslashes($str);
        $res = str_replace($find, $res, $str);
        preg_match_all('~(\$\{"GLOBALS"\}\[[\'"](\w+)[\'"]\])=["\'](\w+)[\'"];~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $res = str_replace([$match[0], '${' . $match[1] . '}'], ['', '$' . $match[3]], $res);
        }

        return $res;
    }

    private function deobfuscateparenthesesString($str)
    {
        $hangs = 5;
        $res = $str;
        $find = '';
        while (preg_match('~for\((\$\w+)=\d+,(\$\w+)=\'([^\$]+)\',(\$\w+)=\'\';@?ord\(\2\[\1\]\);\1\+\+\)\{if\(\1<\d+\)\{(\$\w+)\[\2\[\1\]\]=\1;\}else\{\$\w+\.\=@?chr\(\(\5\[\2\[\1\]\]<<\d+\)\+\(\5\[\2\[\+\+\1\]\]\)\);\}\}\s*.{0,500}eval\(\4\);(if\(isset\(\$_(GET|REQUEST|POST|COOKIE)\[[\'"][^\'"]+[\'"]\]\)\)\{[^}]+;\})?~msi', $res, $matches) && $hangs--) {
            if($hangs == 4) {
                $find = $matches[0];
            }
            $res = '';
            $temp = [];
            $matches[3] = stripcslashes($matches[3]);
            for($i=0, $iMax = strlen($matches[3]); $i < $iMax; $i++)
            {
                if($i < 16) $temp[$matches[3][$i]] = $i;
                else $res .= @chr(($temp[$matches[3][$i]]<<4) + ($temp[$matches[3][++$i]]));
            }
        }
        if(!isset($matches[6])) {
            //$xor_key = 'SjJVkE6rkRYj';
            $xor_key = $res^"\n//adjust sy"; //\n//adjust system variables";
            $res = $res ^ substr(str_repeat($xor_key, (strlen($res) / strlen($xor_key)) + 1), 0, strlen($res));
        }
        if(substr($res,0,12)=="\n//adjust sy") {
            $res = str_replace($find, $res, $str);
            return $res;
        } else return $str;
    }

    private function deobfuscateEvalInject($str, $matches)
    {
        $res = $str;
        $find = $matches[0];
        $alph = $matches[2];

        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace($matches[1] . '[' . $i . '].', "'" . $alph[$i] . "'", $res);
            $res = str_replace($matches[1] . '[' . $i . ']', "'" . $alph[$i] . "'", $res);
        }

        $res = str_replace("''", '', $res);
        $res = str_replace("' '", '', $res);

        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateWebshellObf($str)
    {
        $res = $str;
        preg_match('~function\s*(\w{1,40})\s*\(\s*(\$\w{1,40})\s*,\s*(\$\w{1,40})\s*\)\s*\{\s*(\$\w{1,40})\s*=\s*str_rot13\s*\(\s*gzinflate\s*\(\s*str_rot13\s*\(\s*base64_decode\s*\(\s*[\'"]([^\'"]*)[\'"]\s*\)\s*\)\s*\)\s*\)\s*;\s*(if\s*\(\s*\$\w+\s*==[\'"][^\'"]*[\'"]\s*\)\s*\{\s*(\$\w{1,40})\s*=(\$\w+[\{\[]\d+[\}\]]\.?)+;return\s*(\$\w+)\(\3\);\s*\}\s*else\s*)+\s*if\s*\(\s*\$\w+\s*==[\'"][^\'"]*[\'"]\s*\)\s*\{\s*return\s*eval\(\3\);\s*\}\s*\};\s*(\$\w{1,40})\s*=\s*[\'"][^\'"]*[\'"];(\s*\10\([\'"][^\'"]*[\'"],)+\s*[\'"]([^\'"]*)[\'"]\s*\)+;~msi',$str, $matches);
        $find = $matches[0];

        $alph = str_rot13(gzinflate(str_rot13(base64_decode($matches[5]))));

        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace($matches[4] . '{' . $i . '}.', "'" . $alph[$i] . "'", $res);
            $res = str_replace($matches[4] . '{' . $i . '}', "'" . $alph[$i] . "'", $res);
        }
        $res = base64_decode(gzinflate(str_rot13(convert_uudecode(gzinflate(base64_decode(strrev($matches[12])))))));
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateXorFName($str, $matches, $xor_key = null)
    {
        if (!isset($matches)) {
            preg_match('~(?(DEFINE)(?\'c\'(?:/\*\w+\*/)*))(\$\w+)\s*=\s*basename(?&c)\((?&c)trim(?&c)\((?&c)preg_replace(?&c)\((?&c)rawurldecode(?&c)\((?&c)"[%0-9A-F\.]+"(?&c)\)(?&c),\s*\'\',\s*__FILE__(?&c)\)(?&c)\)(?&c)\)(?&c);(\$\w+)\s*=\s*"([%\w\.\-\~]+)";(?:(\$\w+)=[^;]+;\5(?&c)\((?&c)\'\',\s*\'};\'\s*\.\s*(?&c)\()?(?:eval(?&c)\()?(?&c)rawurldecode(?&c)\((?&c)\3(?&c)\)(?&c)\s*\^\s*substr(?&c)\((?&c)str_repeat(?&c)\((?&c)\2,\s*(?&c)\((?&c)strlen(?&c)\((?&c)\3(?&c)\)(?&c)/strlen(?&c)\((?&c)\2(?&c)\)(?&c)\)(?&c)\s*\+\s*1(?&c)\)(?&c),\s*0,(?&c)\s*strlen(?&c)\((?&c)\3(?&c)\)(?&c)\)(?&c)\)(?:(?&c)\s*\.\s*\'{\'(?&c)\))?(?&c);~msi', $str, $matches);
        }
        $encrypted = rawurldecode($matches[4]);
        if (!isset($xor_key)) {
            $plain_text = '@ini_set(\'error_log\', NULL);';
            $plain_text2 = 'if (!defined(';
            $xor_key = substr($encrypted, 0, strlen($plain_text)) ^ $plain_text;
            if (preg_match('~\.?[a-z0-9-_]{8,}\.\w{3}~', $xor_key, $m)) {
                $xor_key = $m[0];
            } else {
                $xor_key = substr($encrypted, 0, strlen($plain_text2)) ^ $plain_text2;
                if (preg_match('~\.?[a-z0-9-_]{8,}\.\w{3}~', $xor_key, $m)) {
                    $xor_key = $m[0];
                }
            }
        }
        $result = $encrypted ^ substr(str_repeat($xor_key, (strlen($encrypted) / strlen($xor_key)) + 1), 0, strlen($encrypted));
        return $result;
    }

    private function deobfuscateSubstCreateFunc($str)
    {
        preg_match('~(\$\w{1,40})=\'(([^\'\\\\]|\\\\.)*)\';\s*((\$\w{1,40})=(\1\[\d+].?)+;\s*)+(\$\w{1,40})=\'\';\s*(\$\w{1,40})\(\7,\$\w{1,40}\.\"([^\"]+)\"\.\$\w{1,40}\.\5\);~msi', $str, $matches);
        $find = $matches[0];
        $php = base64_decode($matches[9]);
        preg_match('~(\$\w{1,40})=(\$\w{1,40})\("([^\']+)"\)~msi', $php, $matches);
        $matches[3] = base64_decode($matches[3]);
        $php = '';
        for ($i = 1, $iMax = strlen($matches[3]); $i < $iMax; $i++) {
            if ($i % 2) {
                $php .= substr($matches[3], $i, 1);
            }
        }
        $php = str_replace($find, $php, $str);
        return $php;
    }

    private function deobfuscateZeura($str, $matches)
    {
        $offset = (int)$matches[8] + (int)$matches[9];
        $obfPHP = explode('__halt_compiler();', $str);
        $obfPHP = end($obfPHP);
        $php = gzinflate(base64_decode(substr(trim($obfPHP), $offset)));
        $php = stripcslashes($php);
        $php = str_replace($matches[0], $php, $str);
        return $php;
    }

    private function deobfuscateZeuraFourArgs($str, $matches)
    {
        $offset = $matches[6] * -1;
        $res    = gzinflate(base64_decode(substr(trim($str), $offset)));

        return $res;
    }

    private function deobfuscateSourceCop($str, $matches)
    {
        $key = $matches[2];
        $obfPHP = $matches[1];
        $res = '';
        $index = 0;
        $len = strlen($key);
        $temp = hexdec('&H' . substr($obfPHP, 0, 2));
        for ($i = 2, $iMax = strlen($obfPHP); $i < $iMax; $i += 2) {
            $bytes = hexdec(trim(substr($obfPHP, $i, 2)));
            $index = (($index < $len) ? $index + 1 : 1);
            $decoded = $bytes ^ ord(substr($key, $index - 1, 1));
            if ($decoded <= $temp) {
                $decoded = 255 + $decoded - $temp;
            } else {
                $decoded -= $temp;
            }
            $res .= chr($decoded);
            $temp = $bytes;
        }
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateGlobalsArray($str, $matches)
    {
        $res = $str;
        $alph = stripcslashes($matches[3]);
        $res = preg_replace('~\${"[\\\\x0-9a-f]+"}\[\'\w+\'\]\s*=\s*"[\\\\x0-9a-f]+";~msi', '', $res);

        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace([
                $matches[1] . '[' . $matches[2] . ']' . '[' . $i . '].',
                $matches[1] . '[' . $matches[2] . ']' . '[' . $i . ']'
            ], array("'" . $alph[$i] . "'", "'" . $alph[$i] . "'"), $res);
        }
        $res = str_replace("''", '', $res);

        preg_match_all('~(\$\w+)\[(\'\w+\')]\s*=\s*\'(\w+)\';~msi', $res, $funcs);
        foreach ($funcs[1] as $k => $var) {
            if ($var !== $matches[1]) {
                continue;
            }
            $vars[] = $funcs[2][$k];
            $func[] = $funcs[3][$k];
        }

        foreach ($vars as $index => $var) {
            $res = str_replace($matches[1] . '[' . $var . ']', $func[$index], $res);
        }

        foreach ($func as $remove) {
            $res = str_replace($remove . " = '" . $remove . "';", '', $res);
            $res = str_replace($remove . "='" . $remove . "';", '', $res);
        }
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateXbrangwolf($str, $match)
    {
        return $match[0];
    }

    private function deobfuscateObfB64($str, $matches)
    {
        $res = base64_decode($matches[3]);
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateArrayOffsets($str)
    {
        $vars = [];
        preg_match('~(\$\w{1,40})\s*=\s*\'([^\']*)\';\s*(\$\w{1,40})\s*=\s*explode\s*\((chr\s*\(\s*\(\d+\-\d+\)\)),substr\s*\(\1,\s*\((\d+\-\d+)\),\s*\(\s*(\d+\-\d+)\)\)\);.+\1\s*=\s*\$\w+[+\-\*]\d+;~msi', $str, $matches);

        $find = $matches[0];
        $obfPHP = $matches[2];
        $matches[4] = Helpers::calc($matches[4]);
        $matches[5] = (int)Helpers::calc($matches[5]);
        $matches[6] = (int)Helpers::calc($matches[6]);

        $func = explode($matches[4], strtolower(substr($obfPHP, $matches[5], $matches[6])));
        $func[1] = strrev($func[1]);
        $func[2] = strrev($func[2]);

        preg_match('~\$\w{1,40}\s=\sexplode\((chr\(\(\d+\-\d+\)\)),\'([^\']+)\'\);~msi', $str, $matches);
        $matches[1] = Helpers::calc($matches[1]);
        $offsets = explode($matches[1], $matches[2]);

        $res = '';
        for ($i = 0; $i < (sizeof($offsets) / 2); $i++) {
            $res .= substr($obfPHP, $offsets[$i * 2], $offsets[($i * 2) + 1]);
        }

        preg_match('~return\s*\$\w{1,40}\((chr\(\(\d+\-\d+\)\)),(chr\(\(\d+\-\d+\)\)),\$\w{1,40}\);~msi', $str, $matches);
        $matches[1] = Helpers::calc($matches[1]);
        $matches[2] = Helpers::calc($matches[2]);

        $res = Helpers::stripsquoteslashes(str_replace($matches[1], $matches[2], $res));
        $res = "<?php\n" . $res . "?>";

        preg_match('~(\$\w{1,40})\s=\simplode\(array_map\(\"[^\"]+\",str_split\(\"(([^\"\\\\]++|\\\\.)*)\"\)\)\);(\$\w{1,40})\s=\s\$\w{1,40}\(\"\",\s\1\);\s\4\(\);~msi', $res, $matches);

        $matches[2] = stripcslashes($matches[2]);
        for ($i=0, $iMax = strlen($matches[2]); $i < $iMax; $i++) {
            $matches[2][$i] = chr(ord($matches[2][$i])-1);
        }

        $res = str_replace($matches[0], $matches[2], $res);

        preg_match_all('~(\$\w{1,40})\s*=\s*\"(([^\"\\\\]++|\\\\.)*)\";~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $vars[$match[1]] = stripcslashes($match[2]);
        }

        preg_match_all('~(\$\w{1,40})\s*=\s*\'(([^\'\\\\]++|\\\\.)*)\';~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $vars[$match[1]] = Helpers::stripsquoteslashes($match[2]);
        }

        preg_match('~(\$\w{1,40})\s*=\s*\"\\\\x73\\\\164\\\\x72\\\\137\\\\x72\\\\145\\\\x70\\\\154\\\\x61\\\\143\\\\x65";\s(\$\w{1,40})\s=\s\'(([^\'\\\\]++|\\\\.)*)\';\seval\(\1\(\"(([^\"\\\\]++|\\\\.)*)\",\s\"(([^\"\\\\]++|\\\\.)*)\",\s\2\)\);~msi', $res, $matches);

        $matches[7] = stripcslashes($matches[7]);
        $matches[3] = Helpers::stripsquoteslashes(str_replace($matches[5], $matches[7], $matches[3]));


        $res = str_replace($matches[0], $matches[3], $res);

        preg_match_all('~(\$\w{1,40})\s*=\s*\"(([^\"\\\\]++|\\\\.)*)\";~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $vars[$match[1]] = stripcslashes($match[2]);
        }

        preg_match_all('~(\$\w{1,40})\s*=\s*\'(([^\'\\\\]++|\\\\.)*)\';~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $vars[$match[1]] = Helpers::stripsquoteslashes($match[2]);
        }

        preg_match('~\$\w{1,40}\s=\sarray\(((\'(([^\'\\\\]++|\\\\.)*)\',?(\.(\$\w{1,40})\.)?)+)\);~msi', $res, $matches);

        foreach ($vars as $var => $value) {
            $matches[1] = str_replace("'." . $var . ".'", $value, $matches[1]);
        }

        $array2 = explode("','", substr($matches[1], 1, -1));
        preg_match('~eval\(\$\w{1,40}\(array\((((\"[^\"]\"+),?+)+)\),\s(\$\w{1,40}),\s(\$\w{1,40})\)\);~msi', $res, $matches);

        $array1 = explode('","', substr($matches[1], 1, -1));

        $temp = array_keys($vars);
        $temp = $temp[9];

        $arr = explode('|', $vars[$temp]);
        $off=0;
        $funcs=[];

        for ($i = 0, $iMax = count($arr); $i < $iMax; $i++) {
            if ($i === 0) {
                $off = 0;
            } else {
                $off = $arr[$i - 1] + $off;
            }
            $len = $arr[$i];
            $temp = array_keys($vars);
            $temp = $temp[7];

            $funcs[] = substr($vars[$temp], $off, $len);
        }

        for ($i = 0; $i < 5; $i++) {
            if ($i % 2 === 0) {
                $funcs[$i] = strrev($funcs[$i]);
                $g = substr($funcs[$i], strpos($funcs[$i], "9") + 1);
                $g = stripcslashes($g);
                $v = explode(":", substr($funcs[$i], 0, strpos($funcs[$i], "9")));
                for ($j = 0, $jMax = count($v); $j < $jMax; $j++) {
                    $q = explode("|", $v[$j]);
                    $g = str_replace($q[0], $q[1], $g);
                }
                $funcs[$i] = $g;
            } else {
                $h = explode("|", strrev($funcs[$i]));
                $d = explode("*", $h[0]);
                $b = $h[1];
                for ($j = 0, $jMax = count($d); $j < $jMax; $j++) {
                    $b = str_replace($j, $d[$j], $b);
                }
                $funcs[$i] = $b;
            }
        }
        $temp = array_keys($vars);
        $temp = $temp[8];
        $funcs[] = str_replace('9', ' ', strrev($vars[$temp]));
        $funcs = implode("\n", $funcs);
        preg_match('~\$\w{1,40}\s=\s\'.+?eval\([^;]+;~msi', $res, $matches);
        $res = str_replace($matches[0], $funcs, $res);
        $res = stripcslashes($res);
        $res = str_replace('}//}}', '}}', $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateArrayOffsetsEval($str, $matches)
    {
        $arg1 = explode(chr(Helpers::calculateMathStr($matches[4])), $matches[5]);
        $arg2 = $matches[2];
        $code = null;

        for ($enqvlelpmr = 0; $enqvlelpmr < (sizeof($arg1) / 2); $enqvlelpmr++) {
            $code .= substr($arg2, $arg1[($enqvlelpmr * 2)], $arg1[($enqvlelpmr * 2) + 1]);
        }

        $res = str_replace(
            chr(Helpers::calculateMathStr($matches[20])),
            chr(Helpers::calculateMathStr($matches[21])),
            $code
        );

        $arg1 = substr(
            $matches[2],
            Helpers::calculateMathStr($matches[7]),
            Helpers::calculateMathStr($matches[8])
        );

        $func = substr(
            $matches[2],
            Helpers::calculateMathStr($matches[23]),
            Helpers::calculateMathStr($matches[24])
        );

        return $res;
    }

    private function deobfuscateXoredVar($str, $matches)
    {
        $res = $str;
        $find = $matches[0];
        $str = str_replace('\\\'', '@@quote@@', $str);
        preg_match_all('~(\$\w{1,40})\s*=\s*\'([^\']*)\'\s*(?:\^\s*\'([^\']*)\')?;~msi', $str, $matches, PREG_SET_ORDER);
        $vars = [];
        foreach ($matches as $match) {
            $vars[$match[1]] = str_replace('@@quote@@', '\\\'', $match[2]);
            if (isset($match[3])) {
                $vars[$match[1]] ^= str_replace('@@quote@@', '\\\'', $match[3]);
            }
            $res = str_replace($match[0], $match[1] . "='" . $vars[$match[1]] . "';", $res);
        }

        preg_match_all('~(\$\w{1,40})\s*=\s*(\w+);~msi', $str, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $vars[$match[1]] = $match[2];
        }

        preg_match_all('~(\$\w{1,40})\s*=\s*\'([^\']*)\'\^(\$\w+);~msi', $str, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            if (isset($vars[$match[3]])) {
                $vars[$match[1]] = str_replace('@@quote@@', '\\\'', $match[2]) ^ $vars[$match[3]];
                $res = str_replace($match[0], $match[1] . "='" . $vars[$match[1]] . "';", $res);
            }
        }

        preg_match_all('~(\$\w{1,40})\s*=\s*(\$\w+)\^\'([^\']*)\';~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            if (isset($vars[$match[2]])) {
                $vars[$match[1]] = str_replace('@@quote@@', '\\\'', $match[3]) ^ $vars[$match[2]];
                $res = str_replace($match[0], $match[1] . "='" . $vars[$match[1]] . "';", $res);
            }
        }
        preg_match_all('~(?<!\.)\'([^\']*)\'\^(\$\w+)~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            if (isset($vars[$match[2]])) {
                $res = str_replace($match[0], "'" . addcslashes(str_replace('@@quote@@', '\\\'', $match[1]) ^ $vars[$match[2]], '\\\'') . "'", $res);
            }
        }
        preg_match_all('~(\$\w+)\^\'([^\']*)\'~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            if (isset($vars[$match[1]])) {
                $res = str_replace($match[0], "'" . addcslashes($vars[$match[1]] ^ str_replace('@@quote@@', '\\\'', $match[2]), '\\\'') . "'", $res);
            }
        }

        preg_match_all('~(\$\w+)(\.)?=(\$\w+)?(?:\'([^\']*)\')?\.?(\$\w+)?(?:\'([^\']*)\')?(?:\^(\$\w+))?(?:\.\'([^\']*)\')?;~msi', $res, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $val = '';

            //var
            if (isset($match[2]) && $match[2] !== '') {
                if (isset($vars[$match[1]])) {
                    $val .= $vars[$match[1]];
                } else {
                    continue;
                }
            }

            //var
            if (isset($match[3]) && $match[3] !== '') {
                if (isset($vars[$match[3]])) {
                    $val .= $vars[$match[3]];
                } else {
                    continue;
                }
            }

            //str
            if (isset($match[4]) && $match[4] !== '') {
                $val .= $match[4];
            }

            //var
            if (isset($match[5]) && $match[5] !== '') {
                if (isset($vars[$match[5]])) {
                    $val .= $vars[$match[5]];
                } else {
                    continue;
                }
            }

            //str
            if (isset($match[6]) && $match[6] !== '') {
                $val .= $match[6];
            }

            //var and str
            if (isset($match[7]) && $match[7] !== '') {
                if (isset($vars[$match[7]])) {
                    $additionalStr = '';
                    if (isset($match[8]) && $match[8] !== '') {
                        $additionalStr = $match[8];
                    }
                    $val ^= $vars[$match[7]] . $additionalStr;
                } else {
                    continue;
                }
            } else {
                if (isset($match[8]) && $match[8] !== '') {
                    $val .= $match[8];
                }
            }

            $vars[$match[1]] = $val;
            $res = str_replace($match[0], '', $res);
        }

        $res = preg_replace_callback('~(\$\w+)([()]|==)~msi', static function ($match) use ($vars) {
            $res = $vars[$match[1]] ?? $match[1];
            if (isset($vars[$match[1]]) && ($match[2] === ')' || $match[2] === '==')) {
                $res = "'$res'";
            }

            return $res . $match[2];
        }, $res);

        foreach ($vars as $var => $value) {
            $res = str_replace($var, $value, $res);
            $res = str_replace($value . "='" . $value . "';", '', $res);
        }
        $res = str_replace($find, $res, $str);

        if (preg_match('~((\$\w+)=\${\'(\w+)\'};)(?:.*?)((\$\w+)=\2(\[\'[^\']+\'\]);)~msi', $res, $matches)) {
            $res = str_replace($matches[1], '', $res);
            $res = str_replace($matches[4], '', $res);
            $cookieVar = sprintf('$%s%s', $matches[3], $matches[6]);
            $res = str_replace($matches[5], $cookieVar, $res);
        }

        return $res;
    }

    private function deobfuscatePhpMess($str, $matches)
    {
        $res = base64_decode(gzuncompress(base64_decode(base64_decode($matches[4]))));
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscatePregReplaceSample05($str)
    {
        $res = '';
        preg_match('~(\$\w{1,40})\s*=\s*\"([^\"]+)\";\s*\$\w+\s*=\s*\$\w+\(\1,\"([^\"]+)\",\"([^\"]+)\"\);\s*\$\w+\(\"[^\"]+\",\"[^\"]+\",\"\.\"\);~msi', $str, $matches);
        $res = strtr($matches[2], $matches[3], $matches[4]);
        $res = base64_decode($res);
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscatePregReplaceB64($str, $matches)
    {
        $find = $matches[0];
        $res = str_replace($find, base64_decode($matches[4]), $str);
        $res = stripcslashes($res);
        preg_match('~eval\(\${\$\{"GLOBALS"\}\[\"\w+\"\]}\(\${\$\{"GLOBALS"\}\[\"\w+\"]}\(\"([^\"]+)\"\)\)\);~msi', $res, $matches);
        $res = gzuncompress(base64_decode($matches[1]));
        preg_match('~eval\(\$\w+\(\$\w+\("([^"]+)"\)\)\);~msi', $res, $matches);
        $res = gzuncompress(base64_decode($matches[1]));
        preg_match('~eval\(\$\w+\(\$\w+\("([^"]+)"\)\)\);~msi', $res, $matches);
        $res = gzuncompress(base64_decode($matches[1]));
        preg_match_all('~\$(\w+)\s*(\.)?=\s*("[^"]*"|\$\w+);~msi', $res, $matches, PREG_SET_ORDER);
        $var = $matches[0][1];
        $vars = [];
        foreach ($matches as $match) {
            if($match[2]!=='.') {
                $vars[$match[1]] = substr($match[3], 1, -1);
            }
            else {
                $vars[$match[1]] .= $vars[substr($match[3], 1)];
            }
        }
        $res = str_replace("srrKePJUwrMZ", "=", $vars[$var]);
        $res = gzuncompress(base64_decode($res));
        preg_match_all('~function\s*(\w+)\(\$\w+,\$\w+\)\{.+?}\s*};\s*eval\(((\1\(\'(\w+)\',)+)\s*"([\w/\+]+)"\)\)\)\)\)\)\)\);~msi', $res, $matches);
        $decode = array_reverse(explode("',", str_replace($matches[1][0] . "('", '', $matches[2][0])));
        array_shift($decode);
        $arg = $matches[5][0];
        foreach ($decode as $val) {
            $arg = Helpers::someDecoder2($val, $arg);
        }
        $res = $arg;
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateDecoder($str, $matches)
    {
        $res = Helpers::someDecoder($matches[2]);
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateGBE($str)
    {
        preg_match('~(\$\w{1,40})=\'([^\']+)\';\1=gzinflate\(base64_decode\(\1\)\);\1=str_replace\(\"__FILE__\",\"\'\$\w+\'\",\1\);eval\(\1\);~msi', $str, $matches);
        $res = str_replace($matches[0], gzinflate(base64_decode($matches[2])), $str);
        return $res;
    }

    private function deobfuscateGBZ($str, $matches)
    {
        $res = str_replace($matches[0], base64_decode(str_rot13($matches[4])), $str);
        return $res;
    }

    private function deobfuscateBitrix($str, $matches)
    {
        $find       = $matches[0];
        $res        = $str;
        $funclist   = [];
        $strlist    = [];

        $res = preg_replace("|[\"']\s*\.\s*['\"]|smi", '', $res);
        $res = Helpers::replaceMinMaxRound($res, 111);
        $res = Helpers::replaceBase64Decode($res, '"');
        $replace_from = [];
        $replace_to   = [];
        if (preg_match_all('|\$GLOBALS\[[\'"](.+?)[\'"]\]\s*=\s*Array\((.+?)\);|smi', $res, $founds, PREG_SET_ORDER)) {
            foreach ($founds as $found) {
                $varname = $found[1];
                $funclist[$varname] = explode(',', $found[2]);
                $funclist[$varname] = array_map(function ($value) {
                    return trim($value, "'\"");
                }, $funclist[$varname]);

                foreach ($funclist as $var => $funcs) {
                    foreach($funcs as $k => $func) {
                        $replace_from[] = '$GLOBALS["' . $var . '"][' . $k . ']';
                        $replace_from[] = '$GLOBALS[\'' . $var . '\'][' . $k . ']';
                        $replace_to[] = $func;
                        $replace_to[] = $func;
                    }
                }
                $replace_from[] = $found[0];
                $replace_to[] = '';
                $res = str_replace($replace_from, $replace_to, $res);
            }
        }

        $array_temp = [];
        while (preg_match('~function\s*(\w{1,60})\(\$\w+\)\s*{\s*\$\w{1,60}\s*=\s*Array\((.{1,40000}?)\);\s*return\s*base64_decode[^}]+}~msi', $res, $found)) {
            $strlist = explode(',', $found[2]);
            $array_temp[$found[1]] = array_map('base64_decode', $strlist);
            $replace_from = [];
            $replace_to = [];
            foreach($array_temp[$found[1]] as $k => $v) {
                $replace_from[] = $found[1] . '(' . $k . ')';
                $replace_to[] = '\'' . $v . '\'';
            }
            $replace_from[] = $found[0];
            $replace_to[] = '';
            $res = str_replace($replace_from, $replace_to, $res);
        }

        $res = preg_replace('~\'\s*\.\s*\'~', '', $res);
        if (preg_match_all('~\s*function\s*(_+(.{1,60}?))\(\$[_0-9]+\)\s*\{\s*static\s*\$([_0-9]+)\s*=\s*(true|false);.{1,30000}?\$\3\s*=\s*array\((.*?)\);\s*return\s*base64_decode\(\$\3~smi', $res, $founds, PREG_SET_ORDER)) {
            foreach ($founds as $found) {
                $strlist = explode('",', $found[5]);
                $strlist = implode("',", $strlist);
                $strlist = explode("',", $strlist);
                $array_temp[$found[1]] = array_map('base64_decode', $strlist);
                $replace_from = [];
                $replace_to = [];
                foreach($array_temp[$found[1]] as $k => $v) {
                    $replace_from[] = $found[1] . '(' . $k . ')';
                    $replace_to[] = '\'' . $v . '\'';
                }
                $res = str_replace($replace_from, $replace_to, $res);
            }
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateLockIt($str, $matches)
    {
        $phpcode = base64_decode(Helpers::getTextInsideQuotes(Helpers::getEvalCode($str)));
        $result = $str;
        $offset = 0;
        $dictName = $matches[1];
        $dictVal = urldecode($matches[2]);
        $vars = [$dictName => $dictVal];

        $vars = Helpers::getVarsFromDictionaryDynamically($vars, $str);

        if (preg_match('~eval\(~msi', $matches[15])) {
            $phpcode = base64_decode(Helpers::getTextInsideQuotes(Helpers::getEvalCode($matches[15])));
        }

        if ($matches[7] !== '' && preg_match('~eval\(~msi', $matches[7])) {
            $phpcode2 = base64_decode(Helpers::getTextInsideQuotes(Helpers::getEvalCode($matches[7])));
            $vars = Helpers::collectVars($phpcode2, "'", $vars);
        }

        if (preg_match('~\$_F=__FILE__;\$_X=\'([^\']+)\';\s*eval\s*\(\s*\$?\w{1,60}\s*\(\s*[\'"][^\'"]+[\'"]\s*\)\s*\)\s*;~msi', $str, $matches)) {
            $needles = Helpers::getNeedles($phpcode);
            $needle        = $needles[0];
            $before_needle = $needles[1];
            $strToDecode = base64_decode($matches[1]);
            return '<?php ' . strtr($strToDecode, $needle, $before_needle);
        }

        $count = 0;
        preg_match_all('~,(\d+|0x\w+)\)~msi', $phpcode, $offsetMatches, PREG_SET_ORDER);
        if (count($offsetMatches) === 2) {
            foreach ($offsetMatches as $offsetMatch) {
                if (strpos($offsetMatch[1], '0x') !== false && isset($str[$offset + hexdec($offsetMatch[1])])) {
                    $count++;
                    $offset += hexdec($offsetMatch[1]);
                } else if (isset($str[$offset + (int)$offsetMatch[1]])) {
                    $count++;
                    $offset += (int)$offsetMatch[1];
                }
            }
        }

        $finalOffset = 0;
        if (preg_match('~(\$[O0]*)=(\d+|0x\w+);~msi', $str, $match) && $count === 2) {
            if (strpos($match[2], '0x') !== false) {
                $finalOffset = hexdec($match[2]);
            } else {
                $finalOffset = (int)$match[2];
            }
        }

        $result = substr($str, $offset);
        if ($finalOffset > 0) {
            $result = substr($result, 0, $finalOffset);
        }

        if (preg_match('~[\'"]([^\'"]+)[\'"],[\'"]([^\'"]+)[\'"]~msi', $phpcode, $needleMatches)) {
            $result = strtr($result, $needleMatches[1], $needleMatches[2]);
        }

        $result = base64_decode($result);

        $result = Helpers::replaceVarsFromArray($vars, $result, true);

        for ($i = 0; $i < 2; $i++) {
            $result = preg_replace_callback('~eval\s?\(((?:(?:gzinflate|str_rot13|base64_decode)\()+\'[^\']+\'\)+);~msi',
                function ($match) {
                    return $this->unwrapFuncs($match[1]);
                }, $result);

            $result = preg_replace_callback('~eval\s?\((?:str_rot13\()+\'((?|\\\\\'|[^\'])+\')\)\);~msi',
                function ($match) {
                    return str_rot13($match[1]);
                }, $result);
        }

        $result = preg_replace_callback(
            '~(echo\s*)?base64_decode\(\'([\w=\+\/]+)\'\)~',
            function ($match) {
                if ($match[1] != "") {
                    return 'echo \'' . base64_decode($match[2]) . '\'';
                }
                return '\'' . str_replace('\'', '\\\'', base64_decode($match[2])) . '\'';
            },
            $result
        );

        $result = Helpers::replaceVarsFromArray($vars, $result, true);

        return '<?php ' . $result;
    }

    private function deobfuscateB64inHTML($str, $matches)
    {
        $obfPHP        = $str;
        $phpcode       = base64_decode(Helpers::getTextInsideQuotes(Helpers::getEvalCode($obfPHP)));
        $needles       = Helpers::getNeedles($phpcode);
        $needle        = $needles[count($needles) - 2];
        $before_needle = end($needles);
        $pointer1 = $matches[2];
        $temp = strtr($obfPHP, $needle, $before_needle);
        $end = 8;
        for ($i = strlen($temp) - 1; $i > strlen($temp) - 15; $i--) {
            if ($temp[$i] === '=') {
                $end = strlen($temp) - 1 - $i;
            }
        }

        $phpcode = base64_decode(substr($temp, strlen($temp) - $pointer1 - ($end-1), $pointer1));
        $phpcode = str_replace($matches[0], $phpcode, $str);
        return $phpcode;
    }

    private function deobfuscateStrtrFread($str, $layer2)
    {
        $str = explode('?>', $str);
        $str = end($str);
        $res = substr($str, $layer2[1], strlen($str));
        $res = base64_decode(strtr($res, $layer2[2], $layer2[3]));
        $res = str_replace($layer2[0], $res, $str);
        return $res;
    }

    private function deobfuscateStrtrBase64($str, $matches)
    {
        $str = strtr($matches[2], $matches[3], $matches[4]);
        $res = base64_decode($str);
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateByteRun($str)
    {
        preg_match('~\$_F=__FILE__;\$_X=\'([^\']+)\';\s*eval\s*\(\s*\$?\w{1,60}\s*\(\s*[\'"][^\'"]+[\'"]\s*\)\s*\)\s*;~msi', $str, $matches);
        $res = base64_decode($matches[1]);
        $res = strtr($res, '123456aouie', 'aouie123456');
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateExplodeSubst($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        preg_match('~(\$_\w+\[\w+\])\s*=\s*explode\(\'([^\']+)\',\s*\'([^\']+)\'\);.+?(\1\[[a-fx\d]+\])\(\);~msi', $res, $matches);
        $subst_array = explode($matches[2], $matches[3]);
        $res = preg_replace_callback('~((\$_GET\[[O0]+\])|(\$[O0]+))\[([a-fx\d]+)\](\()?~msi', static function ($matches) use ($subst_array) {
            if (isset($matches[5])) {
                return $subst_array[hexdec($matches[4])] . '(';
            }
            return "'" . $subst_array[hexdec($matches[4])] . "'";
        }, $res);
        $res = str_replace($find, $res, $str);

        return $res;
    }

    private function deobfuscateSubst($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        $alph = stripcslashes($matches[2]);

        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace(
                [$matches[1] . '[' . $i . '].', $matches[1] . '[' . $i . ']'],
                ["'" . $alph[$i] . "'", "'" . $alph[$i] . "'"],
                $res
            );
        }
        $res = str_replace("''", '', $res);
        $var = $matches[3];


        preg_match_all('~(\$\w+)\[\]\s*=\s*\'([\w\*\-\#]+)\'~msi', $res, $matches);

        for ($i = 0, $iMax = count($matches[2]); $i <= $iMax; $i++) {
            if ($matches[1][$i] !== $var) {
                continue;
            }
            if (@function_exists($matches[2][$i])) {
                $res = str_replace($var . '[' . $i . ']', $matches[2][$i], $res);
            } else {
                $res = @str_replace($var . '[' . $i . ']', "'" . $matches[2][$i] . "'", $res);
            }
        }
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateUrldecode($str)
    {
        preg_match('~(\$\w+=\'[^\']+\';\s*)+(\$[\w{1,40}]+)=(urldecode|base64_decode)?\(?[\'"]([\w+%=-]+)[\'"]\)?;(\$[\w+]+=(\$(\w+\[\')?[O_0]*(\'\])?([\{\[]\d+[\}\]])?\.?)+;)+[^\?]+(\?\>[\w\~\=\/\+]+|.+\\\\x[^;]+;)~msi', $str, $matches);
        $find = $matches[0];
        $res = $str;
        $res = stripcslashes($res);
        if ($matches[3] === "urldecode") {
            $alph = urldecode($matches[4]);
            $res = str_replace('urldecode(\'' . $matches[4] . '\')', "'" . $alph . "'", $res);
        } elseif ($matches[3] === 'base64_decode') {
            $alph = base64_decode($matches[4]);
            $res = str_replace('base64_decode(\'' . $matches[4] . '\')', "'" . $alph . "'", $res);
        } else {
            $alph = $matches[4];
        }

        for ($i = 0, $iMax = strlen($alph); $i < $iMax; $i++) {
            $res = str_replace([
                    $matches[2] . '[' . $i . '].',
                    $matches[2] . '[' . $i . ']',
                    $matches[2] . '{' . $i . '}.',
                    $matches[2] . '{' . $i . '}'
                ], [
                    "'" . $alph[$i] . "'",
                    "'" . $alph[$i] . "'",
                    "'" . $alph[$i] . "'",
                    "'" . $alph[$i] . "'"],
                $res
            );
        }
        $res = str_replace("''", '', $res);

        preg_match_all('~\$(\w+)\s*=\s*\'([\w\*\-\#]+)\'~msi', $res, $matches, PREG_SET_ORDER);
        for ($i = 0, $iMax = count($matches); $i < $iMax; $i++) {
            $res = str_replace(['$' . $matches[$i][1] . '(' , '${"GLOBALS"}["' . $matches[$i][1] . '"]' . '('],
                $matches[$i][2] . '(', $res, $c);
            $res = str_replace(['$' . $matches[$i][1], '${"GLOBALS"}["' . $matches[$i][1] . '"]'],
                    "'" . $matches[$i][2] . "'", $res, $cc);

            if ($c > 0 || $cc > 0) {
                $res = str_replace([
                    "'" . $matches[$i][2] . "'='" . $matches[$i][2] . "';",
                    $matches[$i][2] . "='" . $matches[$i][2] . "';",
                    $matches[$i][2] . "=" . $matches[$i][2] . ';',
                    $matches[$i][0] . ';'
                ], '', $res);
            }
        }

        $res = Helpers::replaceCreateFunction($res);

        preg_match('~\$([0_O]+)\s*=\s*function\s*\((\$\w+)\)\s*\{\s*\$[O_0]+\s*=\s*substr\s*\(\2,(\d+),(\d+)\);\s*\$[O_0]+\s*=\s*substr\s*\(\2,([\d-]+)\);\s*\$[O_0]+\s*=\s*substr\s*\(\2,(\d+),strlen\s*\(\2\)-(\d+)\);\s*return\s*gzinflate\s*\(base64_decode\s*\(\$[O_0]+\s*\.\s*\$[O_0]+\s*\.\s*\$[O_0]+\)+;~msi', $res, $matches);
        $res = preg_replace_callback('~\$\{"GLOBALS"}\["([0_O]+)"\]\s*\(\'([^\']+)\'\)~msi', static function ($calls) use ($matches) {
            if ($calls[1] !== $matches[1]) {
                return $calls[0];
            }
            $temp1 = substr($calls[2], $matches[3], $matches[4]);
            $temp2 = substr($calls[2], $matches[5]);
            $temp3 = substr($calls[2], $matches[6],strlen($calls[2]) - $matches[7]);
            return "'" . gzinflate(base64_decode($temp1 . $temp3 . $temp2)) . "'";
        }, $res);

        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateUrlDecode3($str, $matches)
    {
        $dictionaryKey = $matches[4];
        $dictionaryVal = urldecode($matches[3]);

        $result = Helpers::replaceVarsFromDictionary($dictionaryKey, $dictionaryVal, $str);

        return $result;
    }

    private function deobfuscateEvalFunc($str)
    {
        $res = $str;
        $res = stripcslashes($res);
        preg_match('~function\s*(\w{1,40})\((\$\w{1,40})\)\s*\{\s*(\$\w{1,40})\s*=\s*\"base64_decode\";\s*(\$\w{1,40})\s*=\s*\"gzinflate\";\s*return\s*\4\(\3\(\2\)\);\s*\}\s*\$\w{1,40}\s*=\s*\"[^\"]*\";\s*\$\w{1,40}\s*=\s*\"[^\"]*\";\s*eval\(\1\(\"([^\"]*)\"\)\);~msi', $res, $matches);
        $res = gzinflate(base64_decode($matches[5]));
        $res = str_replace($str, $res, $str);
        return $res;
    }

    private function deobfuscateEvalConcatFunc($str, $matches)
    {
        $res = $matches[2];

        if (str_replace('"."', '', $matches[6]) === '"create_function"') {
            $brackets = '';
            $res = preg_replace_callback('~[\w."]+\(~', static function ($match) use (&$brackets) {
                $replace = strtolower(str_replace('"."', '', $match[0]));
                if (strpos($replace, 'eval') === false) {
                    $brackets .= ')';
                    return $replace;
                }
                return "";
            }, $res);

            $res .= "'$matches[4]'" . $brackets . ';';
            $res = $this->unwrapFuncs($res);
        }

        return $res;
    }

    private function deobfuscateEvalHex($str)
    {
        preg_match('~eval\s*\("(\\\\x?\d+[^"]+)"\);~msi', $str, $matches);
        $res = stripcslashes($matches[1]);
        $res = str_replace($matches[1], $res, $res);
        $res = str_replace($matches[0], $res, $str);
        return $res;
    }

    private function deobfuscateEvalVarConcat($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        preg_match_all('~(\$\w+)\s*\.?=\s*"([^"]+)";~msi', $str, $matches, PREG_SET_ORDER);
        $vars = [];
        foreach ($matches as $match) {
            $res = str_replace($match[0], '', $res);
            $res = str_replace($match[1], '"' . $match[2] . '"', $res);
        }
        $res = preg_replace('/[\'"]\s*?\.+\s*?[\'"]/smi', '', $res);
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateEvalVarSpecific($str, $matches)
    {
        $res = $str;

        if (preg_match('~\${"[^"]+"}\["[^"]+"\]|\${\${"[^"]+"}\["[^"]+"\]}~msi', $str)) {
            $res = stripcslashes($res);

            preg_match_all('~(\${"[^"]+"}\["[^"]+"\])="([^"]+)";~msi',$res, $match, PREG_SET_ORDER);
            foreach ($match as $m) {
                $res = str_replace('${' . $m[1] . '}', '$' . $m[2], $res);
            }
        }

        $vars = Helpers::collectVars($res);

        if (preg_match('~eval\(htmlspecialchars_decode\(urldecode\(base64_decode\((\$\w+)\)\)\)\);~msi', $res, $m) && isset($vars[$m[1]])) {
            $res = htmlspecialchars_decode(urldecode(base64_decode($vars[$m[1]])));
        }

        $res = Helpers::replaceVarsFromArray($vars, $res, false, true);

        return $res;
    }

    private function deobfuscateEvalVar($str, $matches)
    {
        $find = $matches[0];
        $evalVar = $matches[7];
        if (!$evalVar) {
            $evalVar = $matches[6];
            $pregVal = '\$\w+';
            $pregStr = '[\'"]?([\/\w\+=]+)[\'"]?';
            $pregFunc = '(?:base64_decode\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|htmlspecialchars_decode\s*\()+(?:["\']([\/\w\+=]+)["\'])';
            while (preg_match('~str_replace\(["\']([\/\w]+)["\'],\s?["\']([\/\w\+=]+)["\'],\s?(?|(' . $pregVal . ')|(?:' . $pregStr . ')|(' . $pregFunc . '))\)~msi', $evalVar, $match)) {
                $result = $match[0];
                if (preg_match('~' . $pregVal . '~', $match[3], $arg)) {
                    $result = str_replace($match[1], $match[2], $matches[3]);
                } elseif (preg_match('~' . $pregFunc . '~', $match[3], $arg)) {
                    $unwrappedVar = $this->unwrapFuncs($arg[0]);
                    $result = str_replace($match[1], $match[2], $unwrappedVar);
                } elseif (preg_match('~' . $pregStr . '~', $match[3], $arg)) {
                    $result = str_replace($match[1], $match[2], $match[3]);
                }

                $evalVar = str_replace($match[0], "\"$result\"" . ')', $evalVar);
            }
            return $this->unwrapFuncs($matches[5] . $evalVar);
        }

        $str = str_replace(['\\\'', '\\"'], ['@@slaquote@@', '@@sladquote@@'], $str);
        $val = '';
        $index = 0;
        if (@preg_match_all('~(\$[^\s=\'"\)]+)\s*=\s*\(?(?|("[^"]+")|(\'[^\']+\'))\)?\s*;?~msi', $str, $matches)) {
            $matches[1] = array_reverse($matches[1], true);
            $index = array_search($evalVar, $matches[1], true);
            if ($index !== false) {
                $val = @$matches[2][$index];
            }
        }

        $string = $str;
        if ($val !== '') {
            $string = str_replace($matches[0][$index], '', $string);
            $val = substr($val, 1, -1);
            $var_index = substr_count($string, $evalVar . ' = ');
            $text = "'" . addcslashes(stripcslashes($val), "\\'") . "'";
            preg_match_all('~(\$[^\s=\'"\)]+)(?=[^a-zA-Z0-9])~ms', $string, $matches, PREG_OFFSET_CAPTURE);
            $matches = array_reverse($matches[1]);
            foreach($matches as $match) {
                if ($match[0] === $evalVar) {
                    $string = substr_replace($string, $text, $match[1], strlen($match[0]));
                    break;
                }
            }

            $string = preg_replace_callback('~\(\s*(\$[^\s=\'"\)]+)~msi', static function($m) use ($evalVar, $text) {
                if ($m[1] !== $evalVar) {
                    return $m[0];
                }
                return '(' . $text;
            }, $string);
        }

        $string = str_replace('assert(', 'eval(', $string);
        $string = str_replace('@@slaquote@@', '\\\'', $string);
        $string = str_replace('@@sladquote@@', '\\"', $string);
        $string = str_replace("eval(''.", 'eval(', $string);
        $res = str_replace($find, $string, $str);
        if (strpos($string, 'gzinflate(\'') !== false) {
            $res = $this->deobfuscateEval(stripcslashes($res), []);
        }
        return $res;
    }

    private function deobfuscateEval($str, $matches)
    {
        if (preg_match('~\)+\..{0,30}base64_decode~msi', $str)) {
            $res = explode(').', $str);
            $res = implode(')); eval(', $res);
            return $res;
        }

        if (preg_match('~@?stream_get_contents\(\$\w+\),\s*true~msi', $str, $matches)) {
            if (preg_match('~(\$\w+)\s*=\s*@?fopen\(__FILE__,\s*\'\w+\'\);\s*@?fseek\(\1,\s*([0-9a-fx]+)~msi', $this->full_source, $m)) {
                $offset = hexdec($m[2]);
                $end = substr($this->full_source, $offset);
                $res = str_replace($matches[0], '\'' . $end . '\'', $str);
                return $res;
            }
        }

        $res = $str;
        $group = '';
        if (preg_match('~(preg_replace\(["\'](?:/\.\*?/[^"\']+|[\\\\x0-9a-f]+)["\']\s*,\s*)[^\),]+(?:[\)\\\\0-5]+;[\'"])?(,\s*["\'][^"\']*["\'])\)+;~msi', $res, $matches)) {
            if (strpos(stripcslashes($matches[1]), '(.*)') !== false || strpos(stripcslashes($matches[1]), '(.+)') !== false) {
                $group = substr(stripcslashes($matches[2]), 2, -1);
            }
            $res = str_replace([$matches[1], $matches[2]], ['eval(', ''], $res);
            if ($group !== '' && strpos(stripcslashes($res), '\1') !== false) {
                $res = stripcslashes($res);
                $res = str_replace('\1', $group, $res);
            }
            return $res;
        }

        if (strpos($res, 'e\x76al') !== false
            || strpos($res, '\x29') !== false
            || strpos($res, 'base64_decode("\\x') !== false
        ) {
            $res = stripcslashes($res);
        }
        if (strpos($res, '"."') !== false) {
            $res = str_replace('"."', '', $res);
        }

        if (preg_match('~((\$\w+)\s*=\s*create_function\(\'\',\s*)[^\)]+\)+;\s*(\2\(\);)~msi', $res, $matches)) {
            $res = str_replace($matches[1], 'eval(', $res);
            $res = str_replace($matches[3], '', $res);
            return $res;
        }

        if (preg_match('~eval\s*/\*[\w\s\.:,]+\*/\s*\(~msi', $res, $matches)) {
            $res = str_replace($matches[0], 'eval(', $res);
            return $res;
        }
        if (preg_match('~\$_(POST|GET|REQUEST|COOKIE)~ms', $res)) {
            return $res;
        }

        $res = preg_replace('~"\s+\?>\s*"\s*\.~m', '"?>".', $res, 3);

        $string = substr($res, 5, -2);
        $res = $this->unwrapFuncs($string);

        if (preg_match('~\?>\s*([\w/+]+==)~msi', $res, $match)) {
            $code = base64_decode($match[1]);
            if (strpos($code, 'error_reporting(') !== false) {
                $res = '?> ' . $code;
            }
        }

        if (preg_match('~chr\(\d+\^\d+\)~msi', $res)) {
            $res = Helpers::normalize($res);
        }
        $res = str_replace($str, $res, $str);
        return $res;
    }

    private function deobfuscateEvalCodeFunc($str, $matches)
    {
        $res = substr($str, 5, -2);
        $res = $this->unwrapFuncs($res);
        $res = stripcslashes($res);
        $res = str_replace($str, $res, $str);
        return $res;
    }

    private function deobfuscateEcho($str, $matches)
    {
        $res = $str;
        $string = $matches[0];
        if (preg_match('~\$_(POST|GET|REQUEST|COOKIE)~ms', $res)) {
            return $res;
        }
        $string = substr($string, 5);
        $res = $this->unwrapFuncs($string);
        $res = str_replace($string, '\'' . addcslashes($res, '\'') . '\';', $str);
        return $res;
    }

    private function deobfuscateFOPO($str, $matches)
    {
        $phpcode = Helpers::formatPHP($str);
        $eval = Helpers::getEvalCode($phpcode);
        $b64_count = substr_count($eval, $matches[1]);
        $b64 = Helpers::getTextInsideQuotes($eval);
        for ($i = 0; $i < $b64_count; $i++) {
            $b64 = base64_decode($b64);
        }
        $phpcode = $b64;
        if (preg_match('~eval\s*\(\s*\$[\w|]+\s*\(\s*\$[\w|]+\s*\(~msi', $phpcode)) {
            preg_match_all('~\$\w+\(\$\w+\(\$\w+\("[^"]+"\)+~msi', $phpcode, $matches2);
            $array = end($matches2);
            @$phpcode = gzinflate(base64_decode(str_rot13(Helpers::getTextInsideQuotes(end($array)))));
            $old = '';
            $hangs = 0;
            while (($old != $phpcode) && (strpos($phpcode, 'eval($') !== false)
                   && (strpos($phpcode, '__FILE__') === false) && $hangs < 30) {
                $old = $phpcode;
                $funcs = explode(';', $phpcode);
                if (count($funcs) === 5) {
                    $phpcode = gzinflate(base64_decode(str_rot13(Helpers::getTextInsideQuotes(Helpers::getEvalCode($phpcode)))));
                } elseif (count($funcs) === 4) {
                    $phpcode = gzinflate(base64_decode(Helpers::getTextInsideQuotes(Helpers::getEvalCode($phpcode))));
                }
                $hangs++;
            }
            $res = str_replace($matches[0], substr($phpcode, 2), $str);
        } else {
            $res = str_replace($matches[0], $phpcode, $str);
        }

        return $res;
    }

    private function deobfuscateFakeIonCube($str, $matches)
    {
        $subst_value = 0;
        $matches[1] = Helpers::calc($matches[1]);
        $subst_value = (int)$matches[1] - 21;
        $code = @pack("H*", preg_replace("/[A-Z,\r,\n]/", "", substr($str, $subst_value)));
        $res = str_replace($matches[0], $code, $str);
        return $res;
    }

    private function deobfuscateCobra($str, $matches)
    {
        $find = $matches[0];
        $res = $str;
        $res = preg_replace_callback(
            '~eval\(\"return strrev\(base64_decode\(\'([^\']+)\'\)\);\"\)~msi',
            static function ($matches) {
                return strrev(base64_decode($matches[1]));
            },
            $res
        );

        $res = preg_replace_callback(
            '~eval\(gzinflate\(base64_decode\(\.\"\'([^\']+)\'\)\)\)\;~msi',
            static function ($matches) {
                return gzinflate(base64_decode($matches[1]));
            },
            $res
        );

        preg_match('~(\$\w{1,40})\s*=\s*\"([^\"]+)\"\;\s*\1\s*=\s*explode\(\"([^\"]+)\",\s*\s*\1\);~msi', $res, $matches);
        $var = $matches[1];
        $decrypt = base64_decode(current(explode($matches[3], $matches[2])));
        $decrypt = preg_replace_callback(
            '~eval\(\"return strrev\(base64_decode\(\'([^\']+)\'\)\);\"\)~msi',
            static function ($matches) {
                return strrev(base64_decode($matches[1]));
            },
            $decrypt
        );

        $decrypt = preg_replace_callback(
            '~eval\(gzinflate\(base64_decode\(\.\"\'([^\']+)\'\)\)\)\;~msi',
            static function ($matches) {
                return gzinflate(base64_decode($matches[1]));
            },
            $decrypt
        );

        preg_match('~if\(\!function_exists\(\"(\w+)\"\)\)\s*\{\s*function\s*\1\(\$string\)\s*\{\s*\$string\s*=\s*base64_decode\(\$string\)\;\s*\$key\s*=\s*\"(\w+)\"\;~msi', $decrypt, $matches);

        $decrypt_func = $matches[1];
        $xor_key = $matches[2];

        $res = preg_replace_callback(
            '~\\' . $var . '\s*=\s*.*?eval\(' . $decrypt_func . '\(\"([^\"]+)\"\)\)\;\"\)\;~msi',
            static function ($matches) use ($xor_key) {
                $string = base64_decode($matches[1]);
                $key = $xor_key;
                $xor = "";
                for ($i = 0, $iMax = strlen($string); $i < $iMax;) {
                    for ($j = 0, $jMax = strlen($key); $j < $jMax; $j++,$i++) {
                        if (isset($string[$i])) {
                            $xor .= $string[$i] ^ $key[$j];
                        }
                    }
                }
                return $xor;
            },
            $res
        );
        $res = str_replace($find, $res, $str);
        return $res;
    }

    private function deobfuscateFlamux($str, $matches)
    {
        $str = $matches[0];

        $vars = [];
        preg_match_all('~(\$\w+=[\'"]\w+[\'"];)~', $str, $match);
        foreach ($match[0] as $var) {
            $split = explode('=', str_replace(';', '', $var));
            $vars[$split[0]] = $split[1];
        }

        $res = '';
        preg_match_all('~(\$\w+=\$\w+[\'.]+\$\w+;)~', $str, $match);
        for ($i = 0, $iMax = count($match[0]); $i < $iMax; $i++) {

            $split = explode('=', str_replace(';', '', $match[0][$i]));
            $concats = explode('.', $split[1]);
            $str_to_concat = '';
            foreach ($concats as $concat) {
                $str_to_concat .= $vars[$concat] ?? '';
            }

            $vars[$split[0]] = $str_to_concat;

            if ($i === ($iMax - 1)) {
                $res = gzinflate(base64_decode(base64_decode(str_rot13($str_to_concat))));
            }
        }

        return $res;
    }

    private function deobfuscateDarkShell($str, $matches)
    {
        return stripcslashes($matches[0]);
    }

    private function deobfuscateWso($str, $matches)
    {
        $result = $matches[0];
        $contentVar = $matches[8];

        preg_match_all('~(\[([-+\(\d*\/\)]+)\])+~', $result, $mathMatches);
        foreach ($mathMatches[0] as $index => $match) {
            $search = $mathMatches[2][$index];
            $mathResult = Helpers::calculateMathStr($search);

            $result = str_replace("[$search]", "[$mathResult]", $result);
        }

        $dictionary = $matches[2];

        $variables = Helpers::getVarsFromDictionary($dictionary, $result);
        $variables[$matches[6]] = $matches[7];

        preg_match_all('~(\$\w+)\.=(\$\w+)~', $result, $matches);
        foreach ($matches as $index => $match) {
            $var = $matches[1][$index];
            $value = $matches[2][$index];
            if (!isset($variables[$var])) {
                $variables[$var] = (string)$variables[$value] ?? '';
            } else {
                $variables[$var] .= (string)$variables[$value] ?? '';
            }
        }

        if (isset($variables[$contentVar])) {
            $result = $variables[$contentVar];
        }

        if (preg_match('~(\$\w+)\s+=\s+(["\'\w\/+]+);(\$\w+)=base64_decode\(\1\);(\$\w+)=gzinflate\(\3\);eval\(\4\);~msi', $result, $match)) {
            $result = gzinflate(base64_decode($match[2]));
        }

        $result = str_replace('<?php', '', $result);

        return $result;
    }

    private function deobfuscateAnonymousFox($str, $matches)
    {
        $string = $matches[7];
        $array = strlen(trim($string));
        $debuger = '';
        for ($one = 0; $one < $array; $one += 2) {
            $debuger .= pack("C", hexdec(substr($string, $one, 2)));
        }
        $string = $debuger;

        $result = $string . $matches[8];
        return $result;
    }

    private function deobfuscateWsoEval($str, $matches)
    {
        $result = base64_decode($matches[2]);

        preg_match('~data:image/png;(.*)">~im', $result, $match);
        $result = str_replace( array ('%', '#'), array ('/', '+'), $match[1]);
        $result = gzinflate(base64_decode($result));

        return $result;
    }

    private function deobfuscateAssertStr($str, $matches)
    {
        return 'eval' . $matches[3];
    }

    private function deobfuscateEvalFuncFunc($str, $matches)
    {
        return Helpers::decrypt_T_func(base64_decode($matches[15]));
    }

    private function deobfuscateFuncVar($str, $matches)
    {
        $arg1 = str_replace($matches[5], '', $matches[3]);
        $funcName = str_replace($matches[8], '', $matches[7]);
        $insidefuncName = str_replace($matches[11], '', $matches[10]);

        if ($funcName === 'create_function') {
            $result = sprintf('%s(%s(\'%s\');', $insidefuncName, $arg1, $matches[15]);
        } else {
            $result = sprintf(
                '%s = %s(\'%s\',\'%s(%s(%s));\');%s(\'%s\');',
                $matches[14],
                $funcName,
                $matches[13],
                $insidefuncName,
                $arg1,
                $matches[13],
                $matches[14],
                $matches[15]
            );
        }

        return $result;
    }

    private function deobfuscateEchoEval($str, $matches)
    {
        $content = $matches[4];
        $content = str_replace($matches[1], $matches[2], $content);
        $result = str_replace($matches[3], $content, $matches[5]);

        return $result;
    }

    private function deobfuscateDictionaryVars($str, $matches)
    {
        $dictionary = $matches[2];
        $dictionary = str_replace("\'", "'", $dictionary);
        $dictionary = str_replace('\"', '"', $dictionary);
        $content = $matches[4];
        $vars = Helpers::getVarsFromDictionary($dictionary, $matches[0]);

        if (isset($vars[$matches[6]]) && $vars[$matches[6]] === 'create_function') {
            $content = str_replace($matches[5], 'eval(' . $matches[7] . ');', $content);
        }

        $content = Helpers::replaceVarsFromDictionary($matches[1], $dictionary, $content);

        foreach ($vars as $key => $value) {
            $content = str_replace($key, $value, $content);
        }

        $content = preg_replace_callback('~\${[\'"](\w+)[\'"]}~msi', static function ($m) {
            return '$' . $m[1];
        }, $content);

        $content = str_replace("''}", "\''}", $content);

        return $content;
    }

    private function deobfuscateConcatVarFunc($str, $matches)
    {
        $strVar = "";
        if ($matches['concatVar'] !== "") {
            $strVar = Helpers::concatVariableValues($matches[2], false);
        } else {
            if ($matches['strVal'] !== "") {
                $strVar = $matches['strVal'];
            }
        }

        $result = "";
        $iMax = strlen($strVar) / 2;
        for ($i = 0; $i < $iMax; $i++) {
            $result .= chr(base_convert(substr($strVar, $i * 2, 2), 16, 10));
        }
        return $result;
    }

    private function deobfuscateConcatVarFuncFunc($str, $matches)
    {
        $result = $matches[12];

        $func1 = Helpers::concatVariableValues($matches[2]);
        $func2 = Helpers::concatVariableValues($matches[22]);
        $func3 = Helpers::concatVariableValues($matches[19]);
        $func4 = Helpers::concatVariableValues($matches[7]);

        $result = sprintf('eval(%s(%s(%s(%s("%s")))));', $func1, $func2, $func3, $func4, $result);

        return $result;
    }

    private function deobfuscateEvalVarDoubled($str)
    {
        $result = $str;

        preg_match_all('~(\$\w+)\s?=\s?(\w+)\([\'"]([^\'"]+)[\'"]\);~', $str, $varMatches);

        foreach ($varMatches[0] as $index => $varMatch) {
            $var_name = $varMatches[1][$index];
            $func_name = $varMatches[2][$index];
            $str = $varMatches[3][$index];

            if (Helpers::convertToSafeFunc($func_name)) {
                $str = @$func_name($str);
            }
            $result = str_replace($varMatch, '', $result);
            $result = str_replace($var_name, $str, $result);
        }

        return $result;
    }

    private function deobfuscateVarFuncsEcho($str, $matches)
    {
        $result = $str;
        $func = $matches[2];

        if (Helpers::convertToSafeFunc($func)) {
            $result = @$func($matches[3]);
            $result = str_replace('<?php', '', $result);
        }

        return $result;
    }

    private function deobfuscateVarFuncsMany($str, $matches)
    {
        $result          = $matches[0];
        $strName         = $matches[1];
        $dictionaryName  = $matches[2];
        $dictionaryValue = Helpers::collectStr("$matches[3]", "'");

        $funcs = [];
        $vars  = [];

        $result = preg_replace_callback('~(\$\w+)=((?:(\$\w{1,50})\[?{?\d+\]?}?\.?)+);~msi',
            function ($m) use (&$vars, $dictionaryValue) {
                $vars = array_merge($vars, Helpers::getVarsFromDictionary($dictionaryValue, $m[0]));
                return '';
            }, $result);

        $result = preg_replace_callback(
            '~(\$\w+)\s?=\s?array\([\'"]([\w+\/]+)[\'"]\s?,\s?[\'"]([\w+\/]+)[\'"](?:\s?,[\'"]([\w+\/]+)[\'"]\s?)?\);\s?((?:(?:\$\w+=\s?\w+\(\$\w+,\s?)|(?:return\s?))(join\([\'"]{2},\s?\1\))\s?\)?\s?;)~msi',
            function ($match) {
                $joinedVars = implode("", [$match[2], $match[3], $match[4]]);
                $replace    = str_replace($match[6], "'$joinedVars'", $match[5]);

                return $replace;
            },
            $result
        );

        $result = preg_replace_callback(
            '~global\s(\$\w+);\s?((\$\w+)\s?=\s?[\'"]([\w\/+]+)[\'"];\s?(\$\w+)\s?=\s?[\'"]([\w\/+]+)[\'"];\s?(\$\w+)\s?=\s?[\'"]([\w\/+]+)[\'"];\s?\1\s?\.=\s?"({\3}{\5}{\7})");~',
            function ($match) {
                $concatedVars = $match[4] . $match[6] . $match[8];
                $replace      = str_replace($match[2], sprintf('%s.="%s"', $match[1], $concatedVars), $match[0]);

                return $replace;
            },
            $result
        );

        $result = preg_replace_callback(
            '~((\$\w+)\s?=\s?[\'"]([\w\/+=]+)[\'"];\s?(\$\w+)\s?=\s?[\'"]([\w\/+=]+)[\'"];\s?return\s?"({\2}{\4})");~msi',
            function ($match) {
                $concatedVars = $match[3] . $match[5];
                $replace      = str_replace($match[1], sprintf('return "%s"', $concatedVars), $match[0]);

                return $replace;
            },
            $result
        );

        $result = preg_replace_callback(
            '~(?:class\s(?<className>\w+)\s?{\s?)?(?:public\s)?function\s(?<methodName>\w+\(\)){\s?(?<codeBlock>.*?;)\s}\s?(?:}\s?)?~msi',
            function ($match) use (&$funcs, $strName, $dictionaryName, $dictionaryValue) {
                $str      = "";
                $isConcat = false;

                if (preg_match(
                    '~return\s[\'"]([\w+\/+=]+)[\'"];~msi',
                    $match[0],
                    $returnCode
                )) {
                    $str = $returnCode[1];
                } else {
                    if (preg_match(
                        '~global\s(\$\w+);\s?\1\s?\.=\s?["\']([\w+\/+]+)["\'];?~msi',
                        $match[0],
                        $concatCode
                    )) {
                        $str      = $concatCode[2];
                        $isConcat = true;
                    } else {
                        if (preg_match(
                            '~global\s(\$' . substr(
                                $dictionaryName,
                                1
                            ) . ');\s*return\s*((?:\s?\1\[?{?\d+\]?}?\s?\.?\s?)+);?~msi',
                            $match[0],
                            $returnCode
                        )) {
                            $str      = Helpers::getVarsFromDictionary(
                                $dictionaryValue,
                                sprintf('%s=%s', $dictionaryName, $returnCode[2])
                            );
                            $str      = $str[$dictionaryName];
                            $isConcat = false;
                        }
                    }
                }
                $funcs[$match['methodName']]['str']    = $str;
                $funcs[$match['methodName']]['concat'] = $isConcat;

                return "";
            },
            $result
        );

        $result = preg_replace_callback(
            '~(\$[^' . substr($strName, 1) . ']\w+)\s?=\s?(\w+\(\));~ms',
            function ($match) use ($funcs, &$vars) {
                if (isset($funcs[$match[2]]) && !$funcs[$match[2]]['concat']) {
                    $vars[$match[1]] = $funcs[$match[2]]['str'];
                }
                return "";
            },
            $result
        );

        foreach ($vars as $name => $var) {
            $result = str_replace($name, $var, $result);
        }

        $result = preg_replace_callback(
            '~([\w_]+)\s?\(\s?([\w_]+)\s?\(\s?((?:\$' . substr($dictionaryName,
                1) . '[{\[]\d+[\]}]\s?\.?)+)\s?,\s?(\d+)\s?\),\s?((?:\d+,?)+)\);~msi',
            function ($match) use ($dictionaryValue, $dictionaryName) {
                $str = Helpers::getVarsFromDictionary(
                    $dictionaryValue,
                    sprintf('%s=%s', $dictionaryName, $match[3])
                );
                $res = "";
                if (Helpers::convertToSafeFunc($match[2])) {
                    $res = @$match[2]($str[$dictionaryName], $match[4]);
                }

                if (Helpers::convertToSafeFunc($match[1]) && function_exists($match[1])) {
                    $args   = [$res];
                    $digits = explode(',', $match[5]);
                    foreach ($digits as $digit) {
                        $args[] = (int)$digit;
                    }
                    $reflectionMethod = new ReflectionFunction($match[1]);
                    $res              = $reflectionMethod->invokeArgs($args);
                }
                return "\"$res\";";
            },
            $result
        );

        $strToDecode = "";

        $regexFinal = str_replace('mainVar', $strName,
            '~(?:\mainVar\s?=\s?\w+\(\s?\mainVar\s*,\s?["\'](?<concat>[\w+\/]+)[\'"]\s?\)\s?;)|(?:\mainVar\s?=\s?\w+\(\s?\mainVar\s?,\s?(?<concatFunc>\w+\(\))\)\s?;)|(?:\mainVar\s?\.?=\s?(?:\mainVar\.)?\s?["\'](?<concatStr>[\w+\/=]+)[\'"]\s?;)|(?:\mainVar\s?\.?=\s?(?<concatFuncSingle>\w+\(\))\s?;)|(\$\w+\s?=\s?new\s\w+\(\)\s?;\s?\mainVar\s?\.?=\s?\mainVar\s?\.\s?\$\w+->(?<concatFuncClass>\w+\(\)\s?))|(?:(?<func>[^,\s]\w+\(\)))~msi');

        $result = preg_replace_callback(
            $regexFinal,
            function ($match) use (&$strToDecode, $funcs) {
                if (isset($match['concat']) && $match['concat'] !== "") {
                    $strToDecode .= $match['concat'];
                    return;
                }
                if (isset($match['concatStr']) && $match['concatStr'] !== "") {
                    $strToDecode .= $match['concatStr'];
                    return;
                }
                if (isset($match['concatFunc']) && $match['concatFunc'] !== "") {
                    $strToDecode .= $funcs[$match['concatFunc']]['str'];
                    return;
                }
                if (isset($match['concatFuncSingle']) && $match['concatFuncSingle'] !== "") {
                    $strToDecode .= $funcs[$match['concatFuncSingle']]['str'];
                    return;
                }
                if (isset($match['concatFuncClass']) && $match['concatFuncClass'] !== "") {
                    $strToDecode .= $funcs[$match['concatFuncClass']]['str'];
                    return;
                }
                if (isset($match['func']) && $match['func'] !== "") {
                    $strToDecode .= $funcs[$match['func']]['str'];
                    return;
                }
            },
            $result
        );

        $code   = $result;
        $result = base64_decode($strToDecode);

        if (preg_match('~((\$\w+)="";).*?((\$\w+)=create_function\(\'(\$\w+,\$\w+)\',\s?(base64_decode\(((?:"[\w+=]+"\.?)+)\))\);).*?(\$\w+\s?=\s?create_function\("",\s?\4\(base64_decode\(\2\),\s?(\$_COOKIE\[\'\w+\'\])\)\s?\);)~msi',
            $code, $codeMatch)) {
            $initialCode = base64_decode(Helpers::collectStr($codeMatch[7]));

            $result = sprintf("function %s(%s){%s}%s='%s';%s(%s,%s);",
                substr($codeMatch[4], 1), $codeMatch[5], $initialCode, $codeMatch[2], $result,
                substr($codeMatch[4], 1), $codeMatch[2], $codeMatch[9]);
        }

        return $result;
    }

    private function deobfuscateGlobalArrayEval($str, $matches)
    {
        $result = str_replace($matches[1], "", $str);

        $dictionary = stripcslashes($matches[3]);
        $dictionaryVar = stripcslashes($matches[2]);
        $dictionaryVar = str_replace('{"GLOBALS"}', 'GLOBALS', $dictionaryVar);

        $result = Helpers::replaceVarsFromDictionary($dictionaryVar, $dictionary, $result);

        preg_match_all('~(\$GLOBALS\[[\'\w]+\])\s?=\s?[\'"]?([\w\-\_\$]+)["\']?;\s?~msi', $result, $varMatch);

        foreach ($varMatch[1] as $index => $var) {
            $result = str_replace([$varMatch[0][$index], $varMatch[1][$index]], ["", $varMatch[2][$index]],
                $result);
        }

        return $result;
    }

    private function deobfuscateTinkleShell($str, $matches)
    {
        $result = $str;
        $dictionaryStr = $matches[2];
        $decodeKey = Helpers::getDecryptKeyForTinkleShell(strlen($str));
        $vars = [
            $matches[4] => $matches[5],
        ];

        $result = str_replace(' ', '', $result);
        $matches[3] = str_replace(' ', '', $matches[3]);

        preg_match_all('~(\$\w+)=(?:\$\w+\[\'\w\'\+\d+\+\'\w\'\]\.?)+;~msi', $matches[3], $matchVars);
        foreach ($matchVars[0] as $index => $match) {
            preg_match_all('~\$\w+\[\'\w\'\+(\d+)\+\'\w\'\]\.?~msi', $match, $values);
            foreach ($values[1] as $value) {
                if (!isset($vars[$matchVars[1][$index]])) {
                    $vars[$matchVars[1][$index]] = $dictionaryStr[$value] ?? $value;
                } else {
                    $vars[$matchVars[1][$index]] .= $dictionaryStr[$value] ?? $value;
                }
            }
        }

        $result = str_replace($matches[3], "", $result);

        preg_match_all('~(\$\w+)=(\$\w+)\((\$\w+),(\$\w+)\(""\),"([\w\+]+)"\);~msi', $result, $matchVars);
        foreach ($matchVars[1] as $index => $varName) {
            $func = $vars[$matchVars[2][$index]] ?? $matchVars[2][$index];
            $arg1 = $vars[$matchVars[3][$index]] ?? $matchVars[3][$index];
            $arg2 = $vars[$matchVars[4][$index]] ?? $matchVars[4][$index];
            $argStr = $matchVars[5][$index];

            if (Helpers::convertToSafeFunc($func)) {
                $value = @$func($arg1, $arg2 === 'trim' ? "" : $arg2, $argStr);

                $vars[$varName] = $value;
            }
            $result = str_replace($matchVars[0][$index], '', $result);
        }

        $func = $vars[$matches[10]] ?? '';
        if (Helpers::convertToSafeFunc($func)) {
            $result = @$func($matches[11], $vars[$matches[12]] ?? "", $decodeKey);
        }
        $func = $vars[$matches[7]] ?? '';
        if (Helpers::convertToSafeFunc($func)) {
            $result = @$func($vars[$matches[8]] ?? '', "", $result);
        }
        $func = $vars[$matches[6]] ?? '';
        if (Helpers::convertToSafeFunc($func)) {
            $result = @$func($result);
        }

        return $result;
    }

    private function deobfuscateWsoFunc($str, $matches)
    {
        if (isset($matches['str'])) {
            return gzinflate(base64_decode($matches['str']));
        }

        return $matches[0];
    }

    private function deobfuscateEvalWanFunc($str, $matches)
    {
        $result = gzinflate(base64_decode($matches[5]));

        for ($i = 0, $iMax = strlen($result); $i < $iMax; $i++) {
            $result[$i] = chr(ord($result[$i]) - (int)$matches[4]);
        }

        return $result;
    }

    private function deobfuscateFuncFile($str, $matches)
    {
        return base64_decode($matches[2]);
    }

    private function deobfuscateFuncFile2($str, $matches)
    {
        $var_fragment   = $matches[1];
        $decoded_code   = base64_decode($matches[3]);
        $var_name       = $matches[4];
        $new_fragment   = "$var_name = '$decoded_code';";
        return str_replace($var_fragment, $new_fragment, $str);
    }

    private function deobfuscateGulf($str, $matches)
    {
        $result = str_replace('\'.\'', '', str_replace($matches[2], '', $matches[1]));

        $vars = Helpers::collectVars($matches[2], "'");
        $result = Helpers::replaceVarsFromArray($vars, $result);

        $tempCode = gzinflate(base64_decode($matches[4]));

        $result .= PHP_EOL . $tempCode;

        return $result;
    }

    private function deobfuscateEvalConcatAsciiChars($str, $matches)
    {
        $result = '';

        $num = (int)$matches[2];
        $str = (string)$matches[3];
        $len = strlen($str);

        for ($i = 0; $i < $len; $i++) {
            $result .= chr(ord($str[$i]) ^ $num);
        }

        $result = str_replace(['<?php', '?>', '', ''], '', $result);

        return $result;
    }

    private function deobfuscateEvalPost($str, $matches)
    {
        $vars = Helpers::collectVars($str);

        $result = str_replace('.', "", $matches[8]);
        $result = str_replace($matches[7], "", Helpers::replaceVarsFromArray($vars, $result));
        $result = base64_decode(base64_decode($result));

        return $result;
    }

    private function deobfuscateEvalPregStr($str, $matches)
    {
        $result = sprintf("%s'%s'%s", stripcslashes($matches[1]), $matches[2], stripcslashes($matches[3]));

        $result = $this->unwrapFuncs($result);

        return $result;
    }

    private function deobfuscateClassDestructFunc($str, $matches)
    {
        $result = $str;

        $arg1 = $matches[1] ^ stripcslashes($matches[2]);
        $arg2 = $matches[3] ^ stripcslashes($matches[4]);

        if ($arg1 === 'assert' && $arg2 === 'eval') {
            $result = base64_decode($matches[5]);
        }

        return $result;
    }

    private function deobfuscateCreateFuncEval($str, $matches)
    {
        $result = $str;

        $func = stripcslashes($matches[1]);

        if (Helpers::convertToSafeFunc($func)) {
            $result = @$func($matches[2]);
        }

        return $result;
    }

    private function deobfuscateEvalCreateFunc($str, $matches)
    {
        $result = $str;

        if (!(isset($matches[4]) && $matches[4] !== ''))
        {
            $arr = [
                0 => $matches[5],
                1 => $matches[6],
                2 => $matches[13],
            ];

            $func_1 = Helpers::decodeEvalCreateFunc_2($arr);
            if (strtoupper($func_1) === 'CREATE_FUNCTION') {
                $arr[2] = $matches[10];
                $result = Helpers::decodeEvalCreateFunc_2($arr);
                return $result;
            }
        }

        $arr = [
            0 => $matches[4],
            1 => $matches[5],
            2 => $matches[6],
            3 => $matches[13],
        ];

        $func_1 = Helpers::decodeEvalCreateFunc_1($arr);
        if (strtoupper($func_1) === 'CREATE_FUNCTION') {
            $arr[3] = $matches[10];

            $result = Helpers::decodeEvalCreateFunc_1($arr);

            $result = preg_replace_callback(Helpers::REGEXP_BASE64_DECODE, function ($match) {
                $extraCode = $this->unwrapFuncs($match[0]);

                if (preg_match('~if\(!function_exists\([\'"](\w+)[\'"]\)\){function\s?\1\((\$\w+)\){(\$\w+)=array\(\'([{\w\]]+)\',\'([\w`]+)\',\2\);for\((\$\w+)=0;\6<3;\6\+\+\){for\((\$\w+)=0;\7<strlen\(\3\[\6\]\);\7\+\+\)\s?\3\[\6\]\[\7\]\s?=\s?chr\(ord\(\3\[\6\]\[\7\]\)-1\);if\(\6==1\)\s?\3\[2\]=\3\[0\]\(\3\[1\]\(\3\[2\]\)\);}\s?return\s?\3\[2\];}(\$\w+)=["\']([\w\+\/=]+)["\'];(\$\w+)=[\'"]\1[\'"];(\$\w+)=\10\([\'"]([\w=]+)[\'"]\);\$\w+=\11\(\'\',\10\(\8\)\);\$\w+\(\);}~msi', $extraCode, $matchCode)) {
                    $arr = [
                        0 => $matchCode[4],
                        1 => $matchCode[5],
                        2 => $matchCode[12],
                    ];

                    $func_1 = Helpers::decodeEvalCreateFunc_2($arr);
                    if (strtoupper($func_1) === 'CREATE_FUNCTION') {
                        $arr[2] = $matchCode[9];

                        $extraCode = str_replace($matchCode[0], Helpers::decodeEvalCreateFunc_2($arr), $extraCode);
                    }
                }
                return $extraCode;
            }, $result);
        }

        return $result;
    }

    private function deobfuscateEvalFuncVars($str, $matches)
    {
        $result = $str;
        $vars = Helpers::collectFuncVars($matches[1]);

        $result = Helpers::replaceVarsFromArray($vars, $matches[2]);


        if (strpos($result, 'eval') !== false) {
            $result = $this->unwrapFuncs($result);
        }
        return $result;
    }

    private function deobfuscateDictionaryCreateFuncs($str, $matches)
    {
        $vars = Helpers::getVarsFromDictionary($matches[3], $matches[4]);
        $result = str_replace($matches[4], '', $str);

        $result = preg_replace_callback('~\${"[\\\\\w]+"}\["[\\\\\w]+"\]~msi', static function ($match) {
            return stripcslashes($match[0]);
        }, $result);

        $result = preg_replace_callback('~\${"GLOBALS"}\["(\w+)"\]~msi', static function ($match) use ($vars) {
            $varName = '$' . $match[1];

            return $vars[$varName] ?? $varName;
        }, $result);

        preg_match('~(\$\w+)=create_function\(\'(\$\w+)\',\'\$\w+=substr\(\2,0,5\);\$\w+=substr\(\2,-5\);\$\w+=substr\(\2,7,strlen\(\2\)-14\);return\s*gzinflate\(base64_decode\(\$\w+\.\$\w+\.\$\w+\)\);\'\);~msi', $result, $decoderFunc);
        $result = str_replace($decoderFunc[0], '', $result);
        $decoderFunc = $decoderFunc[1];
        $result = Helpers::replaceCreateFunction($result);
        $result = preg_replace_callback('~(\$\w+)\s*\(\'([^\']+)\'\)~msi', function($m) use ($decoderFunc) {
            if ($m[1] !== $decoderFunc) {
                return $m[0];
            }
            return '\'' . Helpers::dictionarySampleDecode($m[2]) .'\'';
        }, $result);

        $result = Helpers::normalize($result);

        return $result;
    }

    private function deobfuscateEvalPostDictionary($str, $matches)
    {
        $finalCode = $matches[19];
        $result = str_replace($finalCode, '', $str);
        $arrayNum = [];
        $arrayStr = [];

        $regex = '~"?([\w\.\/\s]+)"?,?\s?~msi';
        preg_match_all($regex, $matches[6], $arrayStrMatches);
        foreach ($arrayStrMatches[1] as $arrayStrMatch) {
            $arrayStr[] = $arrayStrMatch;
        }

        $result = Helpers::replaceVarsFromDictionary($matches[5], $arrayStr, $result);
        $vars = Helpers::collectVars($result, "'");

        $regexSpecialVars = '~(\$\w+)([()\]])~msi';
        $code1 = preg_replace_callback($regexSpecialVars, static function ($match) use ($vars) {
            $res = $vars[$match[1]] ?? $match[1];
            if ($match[2] === ']' || $match[2] === ')') {
                $res = "'$res'";
            }
            return $res . $match[2];
        }, $matches[20]);

        $code2 = str_replace($matches[18], '$_POST[\'' . ($vars[$matches[18]] ?? $matches[18]) . '\']', $matches[21]);
        $code2 = Helpers::replaceVarsFromArray($vars, $code2);

        $tempStr = Helpers::replaceVarsFromDictionary($matches[5], $arrayStr, $matches[22]);
        $vars = Helpers::collectVars($tempStr, "'");

        $code3 = preg_replace_callback($regexSpecialVars, static function ($match) use ($vars) {
            $res = $vars[$match[1]] ?? $match[1];
            if ($match[2] === ']' || $match[2] === ')') {
                $res = "'$res'";
            }
            return $res . $match[2];
        }, $matches[23]);

        $result = $code1 . $code2 . $code3;

        return $result;
    }

    private function deobfuscateDropInclude($str, $matches)
    {
        $key = basename($matches[2]);
        $encrypted = base64_decode(base64_decode($matches[4]));
        return $this->deobfuscateXorFName($encrypted, null, $key);
    }

    private function deobfuscateEvalComments($str, $matches)
    {
        return preg_replace('~/\*[^/]*/?\*/~msi', '', $str);
    }

    private function deobfuscateStrrevUrldecodeEval($str, $matches)
    {
        return strrev(urldecode($matches[2]));
    }

    private function deobfuscateEvalPackStrrot($str, $matches)
    {
        return pack("H*", str_rot13($matches[3]));
    }

    private function deobfuscateUrlDecodeTable($str, $matches)
    {
        $matches[3] = str_replace([" ", "\r", "\n", "\t", '\'.\''], '', $matches[3]);
        $matches[5] = str_replace([" ", "'", ">"], '', $matches[5]);
        $temp = explode(',', $matches[5]);
        $array = [];
        foreach ($temp as $value) {
            $temp = explode("=", $value);
            $array[$temp[0]] = $temp[1];
        }
        $res = '';
        for ($i=0, $iMax = strlen($matches[3]); $i < $iMax; $i++) {
            $res .= isset($array[$matches[3][$i]]) ? $array[$matches[3][$i]] : $matches[3][$i];
        }
        $res = substr(rawurldecode($res), 1, -2);
        return $res;
    }

    private function deobfuscateEvalVarChar($str, $matches)
    {
        $chars = Helpers::collectVarsChars($matches[1]);
        $vars = Helpers::assembleStrings($chars, $matches[2]);
        $str = str_replace($matches[1], '', $str);
        $str = str_replace($matches[2], '', $str);
        foreach ($vars as $var => $func) {
            $str = str_replace($var, $func, $str);
        }
        return $str;
    }

    private function deobfuscateEvalVarFunc($str, $matches)
    {
        $var = Helpers::collectFuncVars($matches[1]);
        return $var[$matches[4]];
    }

    private function deobfuscateEvalVarsFuncs($str, $matches)
    {
        $vars = Helpers::collectVars($matches[1]);
        $vars[$matches[5]] = $matches[2];
        $res = Helpers::replaceVarsFromArray($vars, $matches[3]);
        return $res;
    }

    private function deobfuscateEvalFileContent($str, $matches)
    {
        $res = $matches[4];
        $vars = Helpers::getVarsFromDictionary($matches[2], $matches[3]);
        $vars[$matches[1]] = $matches[2];
        $res = Helpers::replaceVarsFromArray($vars, $res);
        if (preg_match('~\$[^=]{0,50}=file\(str_replace\(\'\\\\{2}\',\'/\',__FILE__\)\);(\$[^=]{0,50})=array_pop\(\$[^)]{0,50}\);(\$[^=]{0,50})=array_pop\(\$[^)]{0,50}\);\$[^=]{0,50}=implode\(\'\',\$[^)]{0,50}\)\.substr\(\$[^,]{0,50},0,strrpos\(\$[^,]{0,50},\'@ev\'\)\);\$[^=]{0,50}=md5\(\$[^)]{0,50}\);(?:\$[^=]{0,50}=){0,3}NULL;@eval\(base64_decode\(str_replace\(\$[^,]{0,50},\'\',strtr\(\'~msi',
            $res, $match)) {
            $arr = explode(PHP_EOL, $str);
            foreach ($arr as $index => $val) {
                if ($index !== count($arr) - 1) {
                    $arr[$index] .= PHP_EOL;
                }
            }

            $arr1 = array_pop($arr);
            $arr2 = array_pop($arr);

            $vars[$match[1]] = $arr1;
            $vars[$match[2]] = $arr2;

            $res = implode('', $arr) . substr($arr2, 0, strrpos($arr2, '@ev'));
            $md5 = md5($res);
            $res = base64_decode(str_replace($md5, '', strtr($matches[5], $matches[6], $matches[7])));


            if (preg_match('~eval\((?:\$[^(]{0,50}\(){2}\$[^,]{0,50},\s{0,10}\'([^\']{1,500})\',\s{0,10}\'([^\']{1,500})\'\){3};~msi',
                $res, $match)) {
                $res = Helpers::replaceVarsFromArray($vars, $res);
                if (preg_match('~eval\(base64_decode\(strtr\(~msi', $res)) {
                    $res = base64_decode(strtr($arr1, $match[1], $match[2]));
                    $res = '<?php ' . PHP_EOL . $res;
                }
            }
        }

        return $res;
    }

    private function deobfuscateEvalArrayVar($str, $matches)
    {
        $result = $str;

        $array1 = str_split($matches[3]);
        $array2 = [];
        $arrayStr = (isset($matches[2]) && $matches[2] !== '') ? base64_decode($matches[2]) : $matches[1];

        if (preg_match('~(\$\w+)=\[(["\'][\w\[\];\'"|,.{}+=/&][\'"]=>["\'][\w\[\];\'"|,.{}+=/&][\'"],?\s{0,50})+\];~msi',
            $arrayStr, $match)) {
            preg_match_all('~["\']([\w\[\];\'"|,.{}+=/&])[\'"]=>["\']([\w\[\];\'"|,.{}+=/&])[\'"]~msi', $match[0],
                $arrayMatches);

            foreach ($arrayMatches[1] as $index => $arrayMatch) {
                $array2[$arrayMatches[1][$index]] = $arrayMatches[2][$index];
            }

            $newStr = "";
            foreach ($array1 as $xx) {
                foreach ($array2 as $main => $val) {
                    if ($xx == (string)$val) {
                        $newStr .= $main;
                        break;
                    }
                }
            }

            $result = gzinflate(base64_decode($newStr));
        }

        return $result;
    }

    private function deobfuscateEvalConcatedVars($str, $matches)
    {
        $iter = [2 => $matches[2], 4 => $matches[4], 6 => $matches[6], 12 => $matches[12]];
        foreach ($iter as $index => $item) {
            $matches[$index] = preg_replace_callback('~chr\((\d+)\)~msi', static function ($match) use (&$matches) {
                return '\'' . chr($match[1]) . '\'';
            }, $matches[$index]);

            $matches[$index] = Helpers::concatStr($matches[$index]);
            $matches[$index] = base64_decode($matches[$index]);
        }

        $result = str_replace([$matches[1], $matches[8], $matches[10]], [$matches[2], 0, 0], $matches[7]);

        if (Helpers::convertToSafeFunc($matches[4])) {
            $code = @$matches[4]($matches[6]);
            $code = gzinflate(str_rot13($code));
        } else {
            $code = 'gzinflate(str_rot13(\'' . $matches[4] . '\')));';
        }

        $result .= $matches[12] . $code;

        return $result;
    }

    private function deobfuscateEchoEscapedStr($str, $matches)
    {
        $i = 1;
        $result = $matches[1];
        $result = str_replace('\\\\\\', '\\\\', $result);

        while ($i < 3) {
            if (!preg_match('~(\\\\x[0-9a-f]{2,3})~msi', $result)) {
                break;
            }

            $result = preg_replace_callback('~(\\\\x[0-9a-f]{2,3})~msi', static function ($m) {
                return stripcslashes($m[1]);
            }, $result);

            $i++;
        }

        $result = stripslashes($result);
        $vars = Helpers::collectVars($result);

        $result = preg_replace_callback('~(?<!{)\${[\'"]GLOBALS[\'"]}\[[\'"](\w+)[\'"]\]=[\'"](\w+)[\'"];~msi',
            function ($m) use (&$vars) {
                $vars['$' . $m[1]] = $m[2];

                return '';
            }, $result);

        $result = Helpers::replaceVarsFromArray($vars, $result);

        foreach ($vars as $name => $val) {
            $result = str_replace("$val=\"$val\";", '', $result);
        }

        return $result;
    }

    private function deobfuscateFilePutDecodedContents($str, $matches)
    {
        $res = $str;
        $content = base64_decode($matches[2]);
        $res = str_replace($matches[1], $content, $res);

        $res = preg_replace_callback('~chr\((\d+)\)~msi', static function ($match) use (&$matches) {
            return '\'' . chr($match[1]) . '\'';
        }, $res);

        $res    = Helpers::concatStringsInContent($res);
        $res    = Helpers::replaceBase64Decode($res, '\'');
        $vars   = Helpers::collectVars($res);
        $res    = Helpers::replaceVarsFromArray($vars, $res);
        $res    = Helpers::removeDuplicatedStrVars($res);

        return $res;
    }

    private function deobfuscatePregReplaceStr($str, $matches)
    {
        return stripcslashes($matches[1]);
    }

    private function deobfuscateEvalImplodedArrStr($str, $matches)
    {
        $split = str_split(stripcslashes($matches[2]));
        $map = array_map(static function($str) {
            return chr(ord($str) - 1);
        }, $split);
        return implode($map);
    }

    private function deobfuscatePregReplaceCodeContent($str, $matches)
    {
        $func = stripcslashes($matches[5]);

        $res = $matches[2];

        if (preg_match('~eval\(preg_replace\([\'"]/([^/])/[\'"],\s?[\'"](.*?)[\'"],\s?(\$\w+)\)\);~msi', $func,
            $match)) {
            if ($match[3] === $matches[1]) {
                $res = str_replace($match[1], stripcslashes($match[2]), $res);
            }
        }

        $vars = [];

        $res = preg_replace_callback('~(\$\w+)\s?=\s?([\'"])(.*?)\2;~msi', static function ($m) use (&$vars) {
            $value = $m[3];
            if ($m[2] === '"') {
                $value = stripcslashes($value);
            }

            $vars[$m[1]] = $value;

            return sprintf('%s=\'%s\';', $m[1], $value);
        }, $res);

        $arrayVar = [];
        $arrayVarName = '';

        if (preg_match('~(\$\w+)\s?=\s?array\((?:\'[^\']+\',?)+\);~msi', $res, $m)) {
            $arrayVarName = $m[1];

            preg_match_all('~\'([^\']+)\',?~msi', $m[0], $arrMatch, PREG_PATTERN_ORDER);
            if (isset($arrMatch[1])) {
                foreach ($arrMatch[1] as $arr) {
                    $arrayVar[] = $arr;
                }
            }
        }

        if (preg_match('~(\$\w+)\((\$\w+),\s?(\$\w+)\s?\.\s?\'\(((?:["\']\w+[\'"],?)+)\)[\'"]\s?\.\s?(\$\w+),\s?null\);~msi',
            $res, $match)) {
            $arrayVar2 = [];
            preg_match_all('~[\'"](\w+)[\'"],?~msi', $match[4], $arrMatch2, PREG_PATTERN_ORDER);
            if (isset($arrMatch2[1])) {
                foreach ($arrMatch2[1] as $arr) {
                    $arrayVar2[] = $arr;
                }
            }

            if (isset($vars[$match[5]])
                && (preg_match('~,\s?(\$\w+),\s?(\$\w+)\)\);~msi', $vars[$match[5]], $m)
                    && $m[1] === $arrayVarName
                    && isset($vars[$m[2]])
                )) {
                $res = str_replace($arrayVar2, $arrayVar, $vars[$m[2]]);
            }
        }

        return $res;
    }

    private function deobfuscateSistemitComEnc($str, $matches)
    {
        $matches[4] = base64_decode(base64_decode($matches[4]));
        $res = gzinflate(base64_decode($matches[2]));
        preg_match_all('~\$\w+\s*=\s*\[((\'[^\']+\',?)+)~msi', $matches[4], $replace, PREG_SET_ORDER);
        $find = explode("','", substr($replace[0][1], 1, -1));
        $replace = explode("','", substr($replace[1][1], 1, -1));
        $res = str_replace($find, $replace, $res);
        return $res;
    }

    private function deobfuscateConcatVarsReplaceEval($str, $matches)
    {
        $res = Helpers::concatVariableValues($matches[1]);
        $res = str_replace($matches[5], '', $res);
        $res = base64_decode($res);
        return $res;
    }

    private function deobfuscateEvalVarFunc2($str, $matches)
    {
        return $this->unwrapFuncs($matches[6]);
    }

    private function deobfuscateEvalArrays($str, $matches)
    {
        $res = str_replace('\'\'', '@@empty@@', $str);
        $vars = explode('", "', substr($matches[10], 1, -1));

        $res = preg_replace_callback('~(\$\w+)\[(\d+)\]\s*\.?\s*~msi', static function($m) use ($vars, $matches) {
            if ($m[1] !== $matches[9]) {
                return $m[0];
            }
            return "'" . $vars[(int)$m[2]] . "'";
        }, $res);
        $res = str_replace(['\'\'', '@@empty@@', $matches[8]], ['', '\'\'', ''], $res);
        preg_match_all('~(\$\w+)\s*=\s*\'([^\']+)\';~msi', $res, $m, PREG_SET_ORDER);
        $vars = [];
        foreach ($m as $var) {
            $vars[$var[1]] = '\'' . $var[2] . '\'';
            $res = str_replace($var[0], '', $res);
        }
        $res = Helpers::replaceVarsFromArray($vars, $res);
        return $res;
    }

    private function deobfuscatePregReplaceVar($str, $matches)
    {
        $result = stripcslashes($matches[2]);

        $regex = stripcslashes($matches[1]);
        if ($regex === '.*') {
            return $result;
        }

        $result = preg_replace_callback($regex, static function ($m) {
            return '';
        }, $result);

        return $result;
    }

    private function deobfuscateEvalBinHexVar($str, $matches)
    {
        $func1 = stripcslashes($matches[2]);
        $func2 = stripcslashes($matches[4]);
        $result = '';

        if (Helpers::convertToSafeFunc($func2) && Helpers::convertToSafeFunc($func1)) {
            $result = '?>' . @$func1(@$func2($matches[6]));
        } else {
            $result = sprintf("'?>'.%s(%s('%s');", $func1, $func2, $matches[6]);
        }

        return $result;
    }

    private function deobfuscateEvalFuncTwoArgs($str, $matches)
    {
        $arg1 = base64_decode($matches[5]);
        $arg2 = $matches[6];

        $result = "";
        for ($o = 0, $oMax = strlen($arg1); $o < $oMax;) {
            for ($u = 0, $uMax = strlen($arg2); $u < $uMax; $u++, $o++) {
                $result .= $arg1[$o] ^ $arg2[$u];
            }
        }

        return $result;
    }

    private function deobfuscateEvalVarReplace($str, $matches)
    {
        $res = $matches[3];
        $replaces = explode(';', $matches[4]);
        foreach ($replaces as $replace) {
            if (preg_match('~(\$\w+)=str_replace\(\'([^\']+)\',\s*\'(\w)\',\s*\1\);~msi', $replace, $m)) {
                $res = str_replace($m[2], $m[3], $res);
            }
        }
        $res = base64_decode($res);
        return $res;
    }

    private function deobfuscateEvalPregReplaceFuncs($str, $matches)
    {
        $func1Str = preg_replace('/' . $matches[3] . '/', "", $matches[2]);
        $func2Str = preg_replace('/' . $matches[6] . '/', "", $matches[5]);

        $strToDecode = '';
        preg_match_all('~[\'"]([^\'"]+)[\'"],?~msi', $matches[8], $strMatches, PREG_SET_ORDER);
        foreach ($strMatches as $index => $strMatch) {
            if ($index > 0) {
                $strToDecode .= PHP_EOL;
            }
            $strToDecode .= $strMatch[1];
        }

        $result = '';
        if (Helpers::convertToSafeFunc($func2Str)) {
            $result = @$func2Str($strToDecode);
        }

        if (preg_match('~eval\(\$\w+\);~msi', $func1Str) && Helpers::convertToSafeFunc($func2Str)) {
            $result = @$func2Str($strToDecode);
            $result = stripcslashes($result);
            $vars = Helpers::collectVars($result);
            if (preg_match('~\$\w+=\$\w+\([\'"]\([\'"],__FILE.*?(?:\$\w+\(){3}[\'"][^\'"]+[\'"]\)\)\)\);~msi', $result,
                $m)) {
                $result = $m[0];
            }
            $result = Helpers::replaceVarsFromArray($vars, $result);
            $result = preg_replace_callback('~gzinflate\(base64_decode\(str_rot13\(["\']([^\'"]+)[\'"]\)\)\)~msi',
                function ($m) {
                    return gzinflate(base64_decode(str_rot13($m[1])));
                }, $result);
        }

        return $result;
    }

    private function deobfuscateEvalVarSlashed($str, $matches)
    {
        $vars = Helpers::collectVars($matches[1]);
        $result = Helpers::replaceVarsFromArray($vars, $matches[2]);
        $result = $this->unwrapFuncs($result);

        return $result;
    }

    private function deobfuscateUrlMd5Passwd($str, $matches)
    {
        while(preg_match('~((?:(\$\w+)=\'[^;]+\';)+)~mis', $str, $matches2)) {
            $vars = Helpers::collectVars($matches2[1], "'");
            $str = Helpers::replaceVarsFromArray($vars, $str, true);
            $str = preg_replace_callback('~str_rot13\(urldecode\(\'([%\da-f]+)\'\)\)~mis', static function($m) {
                return "'" . str_rot13(urldecode($m[1])) . "'";
            }, $str);
            $str = str_replace($matches2[0], '', $str);
        }
        return $str;
    }

    private function deobfuscateBlackScorpShell($str, $matches)
    {
        $vars = Helpers::collectVars($matches[2], "'");
        $vars2 = Helpers::collectVars($matches[3], "'");
        array_walk($vars2, static function(&$var) {
            $var = "'$var'";
        });
        $str = gzinflate(base64_decode($vars2[$matches[5]]));
        $str = Helpers::replaceVarsFromArray($vars, $str, true);
        $str = Helpers::replaceVarsFromArray($vars2, $str);
        $str = str_ireplace('assert', 'eval', $str);
        return $str;
    }

    private function deobfuscateManyDictionaryVars($str, $matches)
    {
        $vars = Helpers::collectVars($matches[1], "'");
        $result = $matches[2];

        foreach ($vars as $dictName => $dictVal) {
            $result = preg_replace_callback(
                '~(\$\w+)[\[{][\'"]?(\d+)[\'"]?[\]}]~msi',
                static function ($m) use ($dictVal, $dictName) {
                    if ($m[1] !== $dictName) {
                        return $m[0];
                    }
                    return "'" . $dictVal[(int)$m[2]] . "'";
                },
                $result
            );
        }
        $result = Helpers::replaceVarsFromArray($vars, $result, true, true);
        $result = preg_replace_callback('~(\.?)\s?[\'"]([\w=\+/()\$,;:"\s?\[\]]+)[\'"]\s?~msi', static function ($m) {
            return $m[2];
        }, $result);

        return $result;
    }

    private function deobfuscateEvalBuffer($str, $matches)
    {
        $result = $matches[4];

        preg_match_all('~"([^"]+)"~msi', $matches[2], $arrMatches, PREG_SET_ORDER);

        $array = [];
        foreach ($arrMatches as $arrMatch) {
            $array[] = stripcslashes($arrMatch[1]);
        }

        $result = str_replace($array, '', $result);

        $result = gzinflate(base64_decode($result));

        return $result;
    }

    private function deobfuscateEvalArrayWalkFunc($str, $matches)
    {
        $result = stripcslashes($matches[1]) . '?>' . PHP_EOL;
        $encodedStr = '';

        preg_match_all('~(?:[\'"]([^\'"]{1,500})[\'"])~msi', $matches[2], $arrayMatches, PREG_SET_ORDER);

        foreach ($arrayMatches as $arrayMatch) {
            $encodedStr .= stripcslashes($arrayMatch[1]);
        }

        $result .= base64_decode(str_rot13($encodedStr));

        return $result;
    }

    private function deobfuscateEvalDictionaryVars($str, $matches)
    {
        $result = $str;
        $vars = Helpers::collectVars($matches[1]);
        $vars[$matches[2]] = $matches[3];

        $vars = Helpers::getVarsFromDictionaryDynamically($vars, $matches[1]);

        $func = $vars[$matches[5]] ?? null;
        if ($func && Helpers::convertToSafeFunc($func)) {
            $result = @$func($matches[6]);
        }

        $result = Helpers::replaceVarsFromArray($vars, $result);

        return $result;
    }

    private function deobfuscateEvalSubstrVal($str, $matches)
    {
        $result = strtr(
            substr($matches[2], (int)$matches[3] * (int)$matches[4]),
            substr($matches[2], (int)$matches[5], (int)$matches[6]),
            substr($matches[2], (int)$matches[7], (int)$matches[8])
        );

        return '?> ' . base64_decode($result);
    }

    private function deobfuscateEvalFuncXored($str, $matches)
    {
        $vars = Helpers::collectFuncVars($str);
        $result = Helpers::replaceVarsFromArray($vars, $str);

        if (preg_match('~\$\w+\s?=\s?gzinflate\(base64_decode\(.*?strlen.*?chr\(\(ord.*?\^~msi', $result)) {
            $encodedStr = gzinflate(base64_decode($matches[1]));
            $len = strlen($encodedStr);
            $result = '';
            for ($i = 0; $i < $len; $i++) {
                $result .= chr((ord($encodedStr[$i]) ^ (int)$matches[3]));
            }
        }

        return $result;
    }

    private function deobfuscateEvalFileContentOffset($str, $matches)
    {
        $result = $matches[1];

        $encodedStr = substr($str, (int)$matches[3]);
        $result = str_replace($matches[2], "'$encodedStr'", $result);

        return '<?php ' . $this->unwrapFuncs($result);
    }

    private function deobfuscateEvalFuncExplodedContent($str, $matches)
    {
        $decodedStr = trim(trim($matches[7], ";"), '"');
        $strMD5 = md5($matches[1]);

        $result = base64_decode(
            str_replace($strMD5, '', strtr($decodedStr . $matches[4], $matches[5], $matches[6]))
        );

        return $result;
    }

    private function deobfuscateEvalEncryptedVars($str, $matches)
    {

        $vars_str = preg_replace_callback('~(\d{1,10}\.\d{1,10})\s?\*\s?(\d{1,10})~msi', static function ($m) {
            $res = (double)($m[1]) * (int)$m[2];

            return "'$res'";
        }, $matches[1]);

        $vars_str = str_replace('"', "'", Helpers::normalize($vars_str));

        $vars = Helpers::collectVars($vars_str, "'");
        $vars_str = Helpers::replaceVarsFromArray($vars, $vars_str);
        $vars = Helpers::collectFuncVars($vars_str, $vars);
        $vars_str = Helpers::removeDuplicatedStrVars($vars_str);

        if ($a = preg_match('~(\$\w{1,50})=openssl_decrypt\(base64_decode\([\'"]([^\'"]+)[\'"]\),\'AES-256-CBC\',substr\(hash\(\'SHA256\',[\'"]([^\'"]+)[\'"],true\),0,32\),OPENSSL_RAW_DATA,([^\)]{0,50})\);~msi',
            $vars_str, $varMatch)) {
            $vars[$varMatch[1]] = openssl_decrypt(base64_decode($varMatch[2]), 'AES-256-CBC',
                substr(hash('SHA256', $varMatch[3], true), 0, 32), OPENSSL_RAW_DATA, $varMatch[4]);
        }

        $result = Helpers::replaceVarsFromArray($vars, str_replace(' ', '', $matches[7]));
        $result = str_replace($matches[4], str_replace($matches[5], '', "'$matches[6]'"), $result);

        return $this->unwrapFuncs($result);
    }

    private function deobfuscateEvalLoveHateFuncs($str, $matches)
    {
        $result = $matches[7];
        $result .= gzinflate(base64_decode($matches[4]));

        /* hate function */
        $finalPHPCode = null;
        $problems = explode(".", gzinflate(base64_decode($matches[2])));
        for ($mistake = 0, $mistakeMax = count($problems); $mistake < $mistakeMax; $mistake += strlen($matches[6])) {
            for ($hug = 0, $hugMax = strlen($matches[6]); $hug < $hugMax; $hug++) {
                $past = (int)$problems[$mistake + $hug];
                $present = (int)ord(substr($matches[6], $hug, 1));
                $sweet = $past - $present;
                $finalPHPCode .= chr($sweet);
            }
        }

        $finalPHPCode = gzinflate(base64_decode($finalPHPCode));

        $result .= PHP_EOL . $finalPHPCode;

        return $result;
    }

    private function deobfuscateXoredKey($str, $matches)
    {
        $encrypted = base64_decode($matches[4]);
        $key = $matches[7];
        $res = Helpers::xorWithKey($encrypted, $key);
        $res = base64_decode($res);
        return $res;
    }

    private function deobfuscateEvalGzB64($str, $matches)
    {
        $res = '';
        preg_match_all('~eval\(\$\w+\(\$\w+\(\'([^\']+)\'\)+;~msi', $str, $m, PREG_SET_ORDER);
        foreach ($m as $match) {
            $res .= gzuncompress(base64_decode($match[1])) . "\n";
        }
        return $res;
    }

    private function deobfuscateEvalArrayB64($str, $matches)
    {
        if (preg_match('~function\s*(_\d+)\((\$\w+)\)\s*{(\$\w+)=Array\(\'([^)]+)\'\);return\s*base64_decode\(\3\[\2\]\);~msi', $str, $found)) {
            $strlist = explode("','", $found[4]);
            $res = preg_replace_callback(
                '|(\w+)\((\d+)\)|smi',
                function ($m) use ($strlist, $found) {
                    if ($m[1] !== $found[1]) {
                        return $m[0];
                    }
                    return "'" . addcslashes(base64_decode($strlist[$m[2]]), '\\\'') . "'";
                },
                $str
            );
            $res = str_replace($matches[1], '', $res);
            return $res;
        }
    }

    private function deobfuscateManyBase64DecodeContent($str)
    {
        return Helpers::replaceBase64Decode($str, "'");
    }

    private function deobfuscateEvalEscapedCharsContent($str, $matches)
    {
        $res = $matches[2] . "'" . stripcslashes($matches[1]) . "')";

        return $this->unwrapFuncs($res);
    }

    private function deobfuscateEvalFuncBinary($str, $matches)
    {
        $binaryVals = hex2bin($matches[2]);
        $res = Helpers::decodeEvalFuncBinary($binaryVals);

        return $res;
    }

    private function deobfuscateEvalPackFuncs($str, $matches)
    {
        return stripcslashes($matches[3]) . $matches[4];
    }

    private function deobfuscateParseStrFunc($str, $matches)
    {
        parse_str(Helpers::concatStr($matches[1]), $vars);
        $funcs = ($matches[5] && $matches[5] !== '') ? $matches[5] : $matches[3];
        $res = Helpers::replaceVarsByArrayName($matches[2], $vars, $funcs);
        $res = $this->unwrapFuncs($res . $matches[6] . ')');

        return $res;
    }

    private function deobfuscateEvalGzinflate($str, $match)
    {
        $res = stripcslashes($match[2]);
        $res = str_replace('"."', '', $res);
        return 'eval(' . $res . ');';
    }

    private function deobfuscateFuncVars($str, $matches)
    {
        $key = $matches[3];
        $res = $matches[7];
        $vars = [$matches[4] => preg_replace($matches[5], "", $matches[6])];

        preg_match_all('~(\$\w{1,50})\s?=\s?(?:(\$\w{1,50})\(\)\s?\.\s?)?\w{1,50}\(\\' . $matches[4] .'\(("[^"]+")\)\);~msi',
            $str, $match, PREG_SET_ORDER);
        foreach ($match as $matchVar) {
            $value = Helpers::decodeFuncVars($key,$this->unwrapFuncs($vars[$matches[4]] . '(' . $matchVar[3] . ')'));
            if ($matchVar[2] !== '') {
                $func = $vars[$matchVar[2]] ?? $matchVar[2];
                $value = $func . '() . \'' . $value . '\'';
            }
            $vars[$matchVar[1]] = $value;
        }

        foreach ($vars as $name => $val) {
            $res = str_replace($name, $val, $res);
        }
        return $res;
    }

    private function deobfuscateDictVars($str, $match)
    {
        $res = Helpers::replaceVarsFromDictionary($match[1], $match[2], $match[3]);
        $res = gzinflate(base64_decode(substr($res, 2, -3)));
        return $res;
    }

    private function deobfuscateGotoStrRot13Vars($str, $matches)
    {
        if (isset($matches[2])) {
            $vars = Helpers::collectVars($str);

            preg_match_all('~(\$\w{1,50})\s?=\s?str_rot13\(\1\);~msi', $str, $match, PREG_SET_ORDER);
            foreach ($match as $m) {
                if (isset($vars[$m[1]])) {
                    $vars[$m[1]] = str_rot13($vars[$m[1]]);
                }
            }

            preg_match_all('~(\$\w{1,50})~msi', $matches[2], $match, PREG_SET_ORDER);
            $strToDecode = '';
            foreach ($match as $var) {
                if (isset($vars[$var[1]])) {
                    $strToDecode .= $vars[$var[1]];
                }
            }

            return base64_decode($strToDecode);
        }

        return $str;
    }

    private function deobfuscateDecodedDoubleStrSet($str, $matches)
    {
        $strToDecode1 = '';
        $strToDecode2 = '';

        preg_match_all('~"([^"]+)"~msi', $matches[1], $match, PREG_SET_ORDER);
        foreach ($match as $m) {
            $strToDecode2 .= $m[1];
        }
        preg_match_all('~\'([^\']+)\'~msi', $matches[2], $match, PREG_SET_ORDER);
        foreach ($match as $m) {
            $strToDecode1 .= $m[1];
        }

        return base64_decode($strToDecode1) . PHP_EOL . base64_decode($strToDecode2);
    }

    private function deobfuscateCreateFuncStrrev($str, $matches)
    {
        $res = preg_replace_callback('~strrev\("([^"]+)"\)~msi', static function ($m) {
            return '"' . strrev($m[1]) . '"';
        }, $matches[3]);

        $res = Helpers::concatStringsInContent($res);
        $vars = Helpers::collectVars($res);
        $res = Helpers::replaceVarsFromArray($vars, $res);
        $res = Helpers::removeDuplicatedStrVars($res);

        if (preg_match('~\$\w+=base64_decode\([\'"][^\'"]+[\'"]\);\$\w+=create_function\(\'\$\w+\',\$\w+\);\$\w+\(\$\w+\);~msi',
            $res)) {
            $funcs = base64_decode($matches[5]);
            $res = str_replace($matches[1], '\'' . $matches[2] . '\'', $funcs);
        }

        return $res;
    }

    private function deobfuscateStrrevBase64($str, $matches)
    {
        return strrev($matches[2]);
    }

    private function deobfuscateCustomDecode($str, $matches)
    {
        return str_rot13($matches[2] . $matches[6]);
    }

    private function deobfuscateExpDoorCode($str, $matches)
    {
        $str = str_replace(
                [
                    $matches[1],
                    $matches[3]
                ],
                [
                    str_replace(['"."', '\'.\''], '', $matches[1]),
                    "'" . addcslashes(base64_decode($matches[4]), "'") . "'"
                ],
                $str
        );
        return $str;
    }

    private function deobfuscateAgustus1945($str, $matches)
    {
        return str_replace($matches[1], $matches[4] . '"' . $matches[7] . '"' . $matches[5], $str);
    }

    private function deobfuscateIncludeB64($str, $matches)
    {
        return str_replace($matches[1], "'" . base64_decode($matches[2]) . "'", $str);
    }

    private function deobfuscateDecodeFileContent($str, $matches)
    {
        return gzuncompress(base64_decode($matches[3]));
    }

    private function deobfuscateBase64decodedFuncContents($str, $matches)
    {
        $vars   = Helpers::collectVars($matches[2]);
        $res    = str_replace($matches[2], '', $str);
        $res    = Helpers::replaceVarsFromArray($vars, $res);

        return Helpers::replaceBase64Decode($res, '\'');
    }

    private function deobfuscateEvalVarWithComment($str, $matches)
    {
        $res = str_replace($matches[3], '', $matches[2]);
        $vars = Helpers::collectVars($matches[1]);
        $res = Helpers::replaceVarsFromArray($vars, $res);

        return '?> ' . $this->unwrapFuncs($res);
    }

    private function deobfuscateEvalPackPreg($str, $matches)
    {
        $varsStr = Helpers::replaceVarsFromDictionary($matches[1], $matches[2], $matches[3]);
        $vars = Helpers::collectVars($varsStr, "'");
        if (isset($vars[$matches[6]]) && Helpers::convertToSafeFunc($vars[$matches[6]])) {
            $strToDecode = @$vars[$matches[6]]($matches[2]);
            $strToDecode = preg_replace('~[' . $matches[5] . ']~i', '', $strToDecode);
            $strToDecode = pack('H*', $strToDecode);

            return $strToDecode;
        }

        return $str;
    }

    private function deobfuscateNib2xeh($str, $matches)
    {
        $matches[3] = str_replace("'", '', $matches[3]);
        $matches[5] = str_replace("'", '', $matches[5]);
        $matches[7] = str_replace("'", '', $matches[7]);
        $replace_from = explode(',', $matches[5]);
        $replace_from[] = ',';
        $replace_to = explode(',', $matches[7]);
        $replace_to[] = '';
        $hex = str_replace($replace_from, $replace_to, $matches[3]);
        return hex2bin($hex);
    }

    private function deobfuscateFun256($str, $matches)
    {
        $need_encode_twice  = !isset($matches[4]);
        $replace            = $need_encode_twice ? $str : $matches[1];
        $code               = $need_encode_twice ? $matches[3] : $matches[4];

        $chr = '';
        for ($i = 0; $i < 120; $i++) {
            $chr .= chr($i);
        }
        $encoded = gzinflate(gzinflate(base64_decode($code)));
        if ($need_encode_twice) {
            $encoded = gzinflate(gzinflate(base64_decode($encoded)));
        }
        $encoded_len = strlen ($encoded);
        $hash = sha1(hash('sha256', md5($chr)));
        $hash_len = strlen($hash);
        $result = '';
        for ($i = 0; $i < $encoded_len; $i += 2) {
            $char = hexdec(base_convert(strrev(substr($encoded, $i, 2)), 36, 16));
            if ($j === $hash_len) {
                $j = 0;
            }
            $delta = ord($hash[$j]);
            $j++;
            $result .= chr ($char - $delta);
        }
        $result = str_replace($replace, $result, $str);
        return $result;
    }

    private function deobfuscateCreateFuncObf($str, $matches)
    {
        $str = Helpers::replaceBase64Decode($matches[7], '\'');
        $str = preg_replace_callback('~str_rot13\(\'([^\']+)\'\)~msi', static function($m) {
            return '\'' . str_rot13($m[1]) . '\'';
        }, $str);
        $str = preg_replace_callback('~chr\(([^\)]+)\)~msi', static function($m) {
            return '\'' . Helpers::calc($m[0]) . '\'';
        }, $str);
        $str = str_replace('\'.\'', '', $str);
        return base64_decode(substr($str,1, -1));
    }

    private function deobfuscateEvalFileContentBySize($str, $matches)
    {
        $res = $str;
        $mainContent = str_replace(["\r", "\n"], '', $str);
        $mainContentLen = strlen($mainContent);
        $main_key = $matches[2] . $mainContentLen;

        $str_to_code = base64_decode($matches[3]);
        $code = Helpers::decodeEvalFileContentBySize($str_to_code, $main_key);

        if (preg_match('~\$\w+=strpos\(\$\w+,((?:chr\(\d+\)\.?)+)\);\$\w+=substr\(\$\w+,0,\$\w+\);eval\(\w+\(\w+\("([^"]+)"\),\$\w+\)\);function\s\w+\(\$\w+\){.*?strpos\(\$\w+,\1\);.*?substr\(\$\w+,\$\w+\+(\d)\)\);~msi',
            $code, $match)) {
            preg_match_all('~chr\((\d+\))~msi', $match[1], $chrMatches, PREG_SET_ORDER);

            $find = '';
            foreach ($chrMatches as $chrMatch) {
                $find .= chr((int)$chrMatch[1]);
            }
            $pos = strpos($mainContent, $find);
            $content = substr($mainContent, 0, $pos);

            $code = Helpers::decodeEvalFileContentBySize(base64_decode($match[2]), $main_key);
            if (preg_match('~\$\w+=md5\(\$\w+\)\.\$\w+;~msi', $code)) {
                $key = md5($content) . $mainContentLen;
                $content = base64_decode(substr($mainContent, $pos + (int)$match[3]));
                $res = Helpers::decodeEvalFileContentBySize($content, $key);
            }
        }

        return '<?php ' . $res;
    }

    private function deobfuscateBase64Array($str, $matches)
    {
        $var_name   = $matches[1];
        $el0        = base64_decode($matches[2]);
        $el1        = Helpers::replaceBase64Decode($matches[3], '\'');
        $code       = $matches[4];

        $code = str_replace($var_name . '[0]', '\'' . $el0 . '\'', $code);
        $code = str_replace($var_name . '[1]', $el1, $code);
        $code = Helpers::replaceBase64Decode($code, '\'');

        return $code;
    }

    private function deobfuscateSimpleVarsAndEval($str, $matches)
    {
        $vars_content = $matches[1];
        $eval_content = $matches[2];

        $vars = Helpers::collectVars($vars_content);
        $code = Helpers::replaceVarsFromArray($vars, $eval_content);

        return $this->unwrapFuncs($code);
    }

    private function deobfuscateReplaceFuncWithBase64DecodeArray($str, $matches)
    {
        $nel_function_content   = $matches[3];
        $other_content          = $matches[1] . $matches[4];
        $array_elements         = str_replace('\'.\'', '', $nel_function_content);

        $elements = array_map('base64_decode', explode(',', $array_elements));

        $result = preg_replace_callback('~nel\s*\(\s*(\d+)\s*\)~mis', function($match) use ($elements) {
                $index = $match[1];
                $value = isset($elements[$index]) ? $elements[$index] : null;
                if (!is_null($value)) {
                    if ($value === "\r") {
                        return '"\\r"';
                    }
                    return "'" . addcslashes($value, "'\\") . "'";
                }
                return $match[0];
            }, $other_content
        );

        return Helpers::replaceMinMaxRound($result);
    }

    private function deobfuscateCreateFuncVars($str, $matches)
    {
        $res = Helpers::concatStringsInContent($matches[1]);
        $vars = Helpers::collectVars($res);
        $res = Helpers::replaceVarsFromArray($vars, $matches[2]);

        return $this->unwrapFuncs($res);
    }

    private function deobfuscateJsonDecodedVar($str, $matches)
    {
        $decodedStr = Helpers::replaceBase64Decode($matches[1], 'QUOTE');
        $decodedStr = str_replace("'", "\'", $decodedStr);
        $decodedStr = str_replace("QUOTE", "'", $decodedStr);

        $res = str_replace($matches[1], $decodedStr, $str);

        return $res;
    }

    private function deobfuscateFilePutPureEncodedContents($str, $matches)
    {
        return $this->deobfuscateJsonDecodedVar($str, $matches);
    }

    private function deobfuscateEvalFuncReverse($str, $matches)
    {
        $decodedContent = $matches[5];
        $decodedContent = preg_replace_callback('~eval\((\w+\(\'([^\']+)\'\))\);~msi', function ($m) {
            $strLen = strlen($m[2]);
            $res = '';

            for ($i = 0; $i <= $strLen - 1; $i++) {
                $res .= $m[2][$strLen - $i - 1];
            }

            return str_replace($m[1], $res, $m[0]);
        }, $decodedContent);

        return str_replace($matches[5], $decodedContent, $str);
    }

    private function deobfuscateBase64decodeFuncs($str, $matches)
    {
        $res = $str;
        $res = preg_replace_callback('~\w+\("([^"]+)"\)~msi', function ($m) {
            return "'" . base64_decode($m[1]) . "'";
        }, $res);

        return $res;
    }

    private function deobfuscateEvalCreateFuncWithDictionaryVar($str, $matches)
    {
        $res = Helpers::replaceVarsFromDictionary($matches[1], $matches[2], $str);
        $vars = Helpers::collectVars($res, "'");
        $func = stripcslashes($matches[5]);

        return sprintf('eval(%s(%s(\'%s\'))));', $vars[$matches[3]] ?? $matches[3], $func, $matches[6]);
    }

    private function deobfuscateEvalCreateFuncWithVars($str, $matches)
    {
        $res = Helpers::concatStringsInContent($str);
        $vars = Helpers::collectVars($res, false);
        $res = Helpers::replaceVarsFromArray($vars, $matches[4]);
        $res = Helpers::concatStringsInContent($res);
        $res = preg_replace_callback('~\w+\(((?:[\'"][^\'"]*[\'"],?)+)\)~msi', function ($m) {
            return str_replace(',', '.', $m[1]);
        }, $res);
        $res = Helpers::concatStringsInContent($res);

        return trim($res, "'");
    }

    private function deobfuscateExplodeSubstrGzinflate($str, $matches)
    {
        $obfuscated = explode($matches[3], gzinflate(substr(stripcslashes($matches[4]), hexdec($matches[5]), (int)$matches[6])));
        $str = str_replace($matches[1], '', $str);
        $str = preg_replace_callback('~\$(?:_GET|GLOBALS)[\{\[][^}]+[\}\]][\{\[]([0-9a-fx]+)[\}\]]\]?(\()?~msi', function($m) use ($obfuscated) {
            $index = hexdec($m[1]);
            $func = (isset($m[2]) && $m[2] !== '');
            if ($func) {
                return $obfuscated[$index] . '(';
            } else {
                return '\'' . $obfuscated[$index] . '\'';
            }
        }, $str);
        $str = preg_replace('~define\(\'([^\']+)\',\s*\'[^\']+\'\);\$(?:_GET|GLOBALS)\[\1\]\s*=\s*explode\(\'([^\']+)\',\s*gzinflate\(substr\(\'(.*)\',([0-9a-fx]+),\s*([0-9\-]+)\)\)\);~msi', '', $str);
        $str = Helpers::normalize($str);
        return $str;
    }

    private function deobfuscateBase64Vars($str, $matches)
    {
        $vars = Helpers::collectVars($matches[2], '\'');
        $code = Helpers::replaceVarsFromArray($vars, $matches[5], false, true);
        $code = Helpers::collectStr($code, '\'');
        $code = base64_decode($code);
        $code = str_replace($matches[1], $code, $str);
        return $code;
    }

    private function deobfuscateChr0b($str, $matches)
    {
        $str = preg_replace_callback('~chr\(((0b|0x)?[0-9a-f]+)\)~msi', function($m) {
            if (isset($m[2]) && $m[2] === '0b') {
                return '\'' . chr(bindec($m[1])) . '\'';
            }
            if (isset($m[2]) && $m[2] === '0x') {
                return '\'' . chr(hexdec($m[1])) . '\'';
            }
            return '\'' . chr($m[1]) . '\'';
        }, $str);

        $str = preg_replace_callback('~\(\'(.)\'\^\'(.)\'\)~msi', function($m) {
            return '\'' . ($m[1] ^ $m[2]) . '\'';
        }, $str);

        $str = str_replace('\'.\'', '', $str);
        $str = preg_replace('~\$\{\'([^\']+)\'\}~msi', '\$\1', $str);
        $str = preg_replace_callback('~(\$\w+)\s*=\s*\'str_rot13\';\s*\1\s*=\s*\1\s*\(\'([^\']+)\'\);~msi', function ($m) {
            return $m[1] . ' = ' . '\'' . str_rot13($m[2]) . '\';';
        }, $str);
        return $str;
    }

    private function deobfuscateCreateFuncPlugin($str, $matches)
    {
        return gzinflate(base64_decode($matches[3]));
    }

    private function deobfuscateStrreplaceEval($str, $matches)
    {
        $vars = Helpers::collectFuncVars($matches[1]);
        return Helpers::replaceVarsFromArray($vars, $matches[2]);
    }

    private function deobfuscateHackM19($str, $matches)
    {
        return gzinflate(base64_decode($matches[6]));
    }

    private function deobfuscateEv404($str, $matches)
    {
        return bzdecompress(base64_decode($matches[4]));
    }

    private function deobfuscateSetVars($str, $matches)
    {
        return str_replace($matches[1], gzinflate(base64_decode($matches[5])), $str);
    }

    private function deobfuscateCreateFuncGzB64($str, $matches)
    {
        return gzuncompress(base64_decode($matches[3]));
    }

    private function deobfuscateCreateFuncGzInflateB64($str, $matches)
    {
        return gzinflate(base64_decode($matches[3]));
    }

    private function deobfuscateWsoShellDictVars($str, $matches)
    {
        $vars[$matches[1]] = stripcslashes($matches[2]);
        $res               = Helpers::replaceVarsFromArray($vars, $matches[3]);
        $vars              = Helpers::collectFuncVars($res, $vars, false);
        $res               = Helpers::replaceVarsFromArray($vars, $matches[5]);
        $finalCode         = $this->unwrapFuncs($res);

        $dictVar = Helpers::replaceVarsFromDictionary($matches[4], $vars[$matches[4]] ?? '', $matches[6]);
        $vars    = Helpers::collectVars($dictVar, "'", $vars);
        if (isset($vars[$matches[9]]) && $vars[$matches[9]] === 'rotencode') {
            $vars[$matches[8]] = Helpers::rotencode(base64_decode($matches[10]), -1);
            $dictVar = Helpers::replaceVarsFromDictionary($matches[8], $vars[$matches[8]] ?? '', $matches[11]);
            $dictVar = Helpers::replaceVarsFromDictionary($matches[4], $vars[$matches[4]] ?? '', $dictVar);
            $vars    = Helpers::collectVars($dictVar, "'", $vars);

            $res = $this->unwrapFuncs(Helpers::replaceVarsFromArray($vars, $matches[12]));

            $count = 10;
            while ($count > 0 && preg_match('~@?eval\(\$\w+\(\$\w+\(["\'][^\'"]+[\'"]\)\)\);~msi', $res, $match)) {
                $res = $this->unwrapFuncs(Helpers::replaceVarsFromArray($vars, $res));
                $count--;
            }

            return $res;
        }

        return $str;
    }

    private function deobfuscateFuncDictVars($str, $matches)
    {
        $vars[$matches[1]] = stripcslashes($matches[2]);

        $vars[$matches[3]] = explode($matches[4], $matches[5]);
        foreach ($vars[$matches[3]] as $i => $k) {
            $temp          = preg_split("//", $k, -1, PREG_SPLIT_NO_EMPTY);
            $vars[$matches[3]][$i] = implode("", array_reverse($temp));
        }

        $iterVar = explode($matches[7], $matches[8]);
        foreach ($iterVar as $i => $k) {
            $vars[$k] = $vars[$matches[3]][$i];
        }

        $vars[$matches[1]] = Helpers::decodefuncDictVars($vars[$matches[1]], -2);
        $dictVar = Helpers::replaceVarsFromDictionary($matches[1], $vars[$matches[1]] ?? '', $matches[15]);
        $vars    = Helpers::collectVars($dictVar, "'", $vars);

        $dictVar = Helpers::getVarsFromDictionaryDynamically($vars, $matches[20]);
        $vars    = Helpers::collectVars($dictVar, "'", $vars);

        $res = Helpers::decodefuncDictVars($matches[23], 1);
        if (isset($vars[$matches[22]]) && Helpers::convertToSafeFunc($vars[$matches[22]])) {
            $res = @$vars[$matches[22]]($res);
            $res = Helpers::replaceVarsFromArray($vars, $res);
        }

        if (preg_match('~\$\w+="([^"]+)";@eval\(\'\?>\'\.gzuncompress\(base64_decode\(strtr\(substr\(\$\w+,(\d+[+\-*/]\d+)\),substr\(\$\w+,(\d+),(\d+)\),\s?substr\(\$\w+,(\d+),(\d+)\)\)\)\)\);~msi',
                       $res, $match)) {
            $res = '?> ' . gzuncompress(base64_decode(
                strtr(
                    substr($match[1], (int)Helpers::calculateMathStr($match[2])),
                    substr($match[1], (int)$match[3], (int)$match[4]),
                    substr($match[1], (int)$match[5], (int)$match[6])))
                );
        }

        return $res;
    }

    private function deobfuscateSec7or($str, $matches)
    {
        $res = $this->unwrapFuncs($matches[3] . $matches[6] . $matches[4] . ';');
        for($i=0, $iMax = strlen($res); $i < $iMax; $i++) {
            $res[$i] = chr(ord($res[$i]) - (int)$matches[5]);
        }
        return $res;
    }

    private function deobfuscateLinesCond($str, $matches)
    {
        $vars_str = $this->unwrapFuncs($matches[1]);
        preg_match_all('~((?:\$\w+=)+)__LINE__==\s*(?:\d+[-+]?)+\s*\?\s*base64_decode\("([^"]+)"\)~msi', $vars_str, $m, PREG_SET_ORDER);
        $vars = [];
        foreach ($m as $var) {
            $func = base64_decode($var[2]);
            $tmp = explode('=', $var[1]);
            array_pop($tmp);
            $vars[] = array_combine(array_values($tmp), array_fill(0, count($tmp), $func));
        }
        $vars = array_merge(...$vars);
        $res = preg_replace_callback('~eval\(\$\w+\(\$\w+\("[^"]+"\)\)\);~msi', function ($m) use ($vars) {
            while (preg_match('~eval\(\$\w+\(\$\w+\("[^"]+"\)\)\);~msi', $m[0])) {
                $m[0] = $this->unwrapFuncs(Helpers::replaceVarsFromArray($vars, $m[0]));
            }
            return $m[0];
        }, $matches[3]);
        $tmp = [];
        $vars = Helpers::collectVars($res, '"', $tmp, true);
        $res = Helpers::replaceVarsFromArray($vars, $res, false, true);
        $vars = Helpers::collectVars($res, '\'', $tmp, true);
        $res = Helpers::replaceVarsFromArray($vars, $res, false, true);
        return $res;
    }

    private function deobfuscateClassWithArrays($str, $matches)
    {
        preg_match_all('~"[^"]+"=>"([^"]+)"~msi', $matches[2], $m);
        $data = implode('', array_reverse($m[1]));
        $data = gzuncompress(base64_decode($data));

        $numberSubstr = 14;
        if (preg_match('~,\((\d+/\d+)\)\);return~msi', $str, $calcMatch)) {
            $numberSubstr = (int)Helpers::calculateMathStr($calcMatch[1]);

        }
        for ($i = 0, $iMax = strlen($data); $i < $iMax; $i++) {
            if(isset($data[$i])) {
                $param3 = ord($data[$i]);
                $data[$i] = chr($param3 - $numberSubstr);
            }
        }
        $res = gzuncompress(base64_decode(strrev(gzinflate($data))));
        return $res;
    }

    private function deobfuscateGotoBase64Decode($str)
    {
        $res = $str;
        $hop = 5;

        while ($hop > 0 && preg_match(Helpers::REGEXP_BASE64_DECODE, $res)) {
            $res = preg_replace_callback(Helpers::REGEXP_BASE64_DECODE, function ($match) {
                $code = base64_decode(stripcslashes($match[1]));
                return '"' . Helpers::unwrapGoto($code) . '"';
            }, $res);

            $hop--;
        }

        return $res;
    }

    private function deobfuscateGotoB64Xor($str, $matches)
    {
        return Helpers::unwrapGoto($str);
    }

    private function deobfuscateAssertStrrev($str, $matches)
    {
        return str_replace($matches[1], strrev($matches[4]), $str);
    }

    private function deobfuscateB64strtr($str, $matches)
    {
        $code = $matches[4];
        $delta = (int)$matches[1];
        $code = str_split($code);
        foreach ($code as &$c) {
            $c = chr(ord($c) + $delta);
        }
        $code = implode('', $code);
        $code = strtr($code, $matches[2], $matches[3]);
        $code = base64_decode($code);
        preg_match('~(\$\w+)="([^"]+)";@eval\(\'\?>\'\.gzuncompress\((?:\$\w+\()+\$\w+,(\$\w+)\*2\),(\$\w+)\(\1,\3,\3\),\s*\4\(\1,0,\3\)+;~mis', $code, $m);
        $code = gzuncompress(base64_decode(strtr(substr($m[2],52*2),substr($m[2],52,52), substr($m[2],0,52))));
        $res = Helpers::unwrapGoto($code);
        return $res;
    }

    private function deobfuscateGzB64strReplaceDataImage($str, $matches)
    {
        $strToDecode = str_replace([$matches[2], $matches[3]], [$matches[4], $matches[5]], $matches[7]);

        $res = gzinflate(base64_decode($strToDecode));

        return $res;
    }

    private function deobfuscateSerializeFileContent($str, $matches)
    {
        return base64_decode(strrev(str_rot13($matches[2])));
    }

    private function deobfuscateGlobalVarsManyReplace($str, $matches)
    {
        $vars = Helpers::collectVars($matches[1]);

        foreach ($vars as &$var) {
            $var = base64_decode(strrev(str_rot13($var)));
        }

        $res = Helpers::replaceVarsFromArray($vars, $matches[2], true, true);

        return $res;
    }

    private function deobfuscateConcatVarsPregReplace($str, $matches)
    {
        $vars = [];

        $vars = Helpers::collectConcatedVars($str, '"', $vars);
        $res = Helpers::replaceVarsFromArray($vars, $matches[3], true, true);
        $res = $this->unwrapFuncs($res);

        return $res;
    }

    private function deobfuscateFilePutContentsB64Decoded($str, $matches)
    {
        $res = $str;
        $vars = [];

        $vars = Helpers::collectConcatedVars($res, '"', $vars, true);

        $res = Helpers::replaceVarsFromArray($vars, $res, true, true);
        $res = Helpers::replaceBase64Decode($res, '"');

        return $res;
    }

    private function deobfuscateFwriteB64DecodedStr($str, $matches)
    {
        $res = $str;
        $vars = [];

        $vars = Helpers::collectFuncVars($res, $vars, false, true);
        $res = Helpers::replaceVarsFromArray($vars, $res, true, true);

        return $res;
    }

    private function deobfuscateFilePutContentsB64Content($str, $matches)
    {
        $res = Helpers::replaceBase64Decode($str, "'");

        return $res;
    }

    private function deobfuscateChrDictCreateFunc($str, $matches)
    {
        $vars = [];

        preg_match_all('~chr\((\d+)\)~msi', $matches[3], $chrs, PREG_SET_ORDER);

        $dictVar = '';
        foreach ($chrs as $chr) {
            $dictVar .= chr((int)$chr[1]);
        }

        $res = Helpers::replaceVarsFromDictionary($matches[2], $dictVar, $matches[6]);
        $res = str_replace('\\\'', "'", $res);
        $res = Helpers::replaceBase64Decode($res, "'");
        $res = substr($res, 1);
        $res = substr($res, 0, -1);

        return $res;
    }

    private function deobfuscateStrReplaceFuncsEvalVar($str, $matches)
    {
        $func = str_replace($matches[3], '', $matches[2]);

        if ($func === 'base64_decode') {
            return base64_decode($matches[4]);
        }

        return $str;
    }

    private function deobfuscateB64SlashedStr($str, $matches)
    {
        return stripcslashes(base64_decode(stripcslashes($matches[1])));
    }

    private function deobfuscateB64ArrayStrEval($str, $matches)
    {
        return base64_decode($matches[4]);
    }

    private function deobfuscateDictVarsPregReplaceB64($str, $matches)
    {
        $res = Helpers::replaceVarsFromDictionary($matches[1], $matches[2], $str);

        if (strpos($res, 'preg_replace') &&
            strpos($res, 'eval') &&
            strpos($res, 'base64_decode')) {
            return base64_decode($matches[3]);
        }

        return $res;
    }

    private function deobfuscateEvalVarB64($str, $matches)
    {
        return gzinflate(base64_decode($matches[3]));
    }

    private function deobfuscateDecodeAChar($str, $matches)
    {
        $res = str_replace($matches[1], '', $str);
        while (strpos($res, 'eval(' . $matches[2] . '(\'') !== false) {
            $res = preg_replace_callback('~eval\(\w+\(\'([^\']+)\'\)\);~msi', function ($m) {
                return Helpers::decodeACharCustom($m[1]);
            }, $res);
        }
        $vars = Helpers::collectVars($res, '\'');
        foreach ($vars as $var => $value) {
            if (strpos($res, $matches[2] . '(' . $var . ')') !== false) {
                $res = str_replace($var . '=\'' . $value . '\';', '', $res);
                $res = str_replace($matches[2] . '(' . $var . ')', '\'' . addcslashes(Helpers::decodeACharCustom($value), '\'') . '\'', $res);
            }
        }
        return $res;
    }

    private function deobfuscateStrReplaceCreateFunc($str, $matches)
    {
        $res = $matches[7];
        $funcs = str_replace($matches[3], 'str_replace', $matches[4]);
        $vars = Helpers::collectFuncVars($funcs, $vars, false);
        $vars[$matches[1]] = '\'' . $matches[2] . '\'';
        foreach ($vars as $var => $value) {
            $res = str_replace($var, $value, $res);
        }
        return 'eval(' . $res . ');';
    }

    private function deobfuscateEvalbin2hex($str, $matches)
    {
        $res = hex2bin($matches[5]) . $matches[6];
        $res = $this->unwrapFuncs($res);
        if (preg_match('~define\(\'([^\']+)\', \'[^\']+\'\);\$GLOBALS\[\1\]\s*=\s*explode\(\'([^\']+)\',\s*gzinflate\(substr\(\'((?:[^\']*\\\\\')+[^\']+)\',([0-9a-fx]+),\s*([\-0-9a-f]+)\)~msi', $res, $m)) {
            $m[3] = stripcslashes($m[3]);
            $strings = explode($m[2], gzinflate(substr($m[3], hexdec($m[4]), (int)$m[5])));
            $res = str_replace($m[0], '', $res);
            $res = preg_replace_callback('~\$GLOBALS[\{\[].[\}\]][\[\{]([0-9a-fx]+)[\]\}]~msi', function($m) use ($strings) {
                return '\'' . $strings[hexdec($m[1])] . '\'';
            }, $res);
        }

        if (substr_count($res, 'goto ') > 50) {
            $res = Helpers::unwrapGoto($res);
        }
        return $res;
    }

    private function deobfuscateManyFuncsWithCode($str, $matches)
    {
        $funcs = [$matches[1] => 'decode'];

        preg_match_all('~function\s(\w{1,50})\((?:\$\w{1,50},?\s?)+\)\s?{\s?return\s\$\w{1,50};\s?}~msi', $res,
                       $funcMatches, PREG_SET_ORDER);

        foreach ($funcMatches as $funcMatch) {
            $funcs[$funcMatch[1]] = 'single_var';
        }

        $res = preg_replace_callback('~(\w{1,50})\s?\(\s?[\'"]([^\'"]+)[\'"]\s?\)~msi', function ($m) use ($funcs) {
            $func = $funcs[$m[1]] ?? false;
            if (!$func) {
                return $m[0];
            }
            if ($func === 'decode') {
                $decoded = "";
                for ($i = 0; $i < strlen($m[2]) - 1; $i += 2) {
                    $decoded .= chr(hexdec($m[2][$i] . $m[2][$i + 1]) ^ 0x66);
                }

                return '"' . $decoded . '"';
            } elseif ($func === 'single_var') {
                return '"' . $m[2] . '"';
            }
        }, $str);

        return $res;
    }

    private function deobfuscateManyGlobals($str, $matches)
    {
        $vars = [];
        foreach ([$matches[1], $matches[2], $matches[3]] as $m) {
            $hangs = 50;
            $part = $m;
            while (strpos($part, 'base64_decode') !== false && $hangs--) {
                $part = Helpers::replaceVarsFromArray($vars, $part);
                $part = Helpers::replaceBase64Decode($part);
            }
            $ops = explode(';', $part);
            foreach ($ops as $v) {
                if ($v === '') {
                    continue;
                }
                $tmp = explode('=', $v, 2);
                $vars[$tmp[0]] = $tmp[1];
            }
        }
        $res = str_replace([$matches[1], $matches[2], $matches[3]], '', $str);
        $hangs = 50;
        while (strpos($res, '$GLOBALS') !== false && $hangs--) {
            $res = str_replace(array_keys($vars), array_values($vars), $res);
        }
        $res = str_replace('base64_decode(\'\')', '\'\'', $res);
        return $res;
    }

    private function deobfuscateB64xoredkey($str, $matches)
    {
        $b64 = Helpers::collectConcatedVars($matches[2]);
        $b64 = $b64[key($b64)];
        $res = Helpers::xorWithKey(base64_decode($b64), $matches[10]);
        return $matches[1] . $res;
    }

    private function deobfuscateGzB64Func($str, $matches)
    {
        $res = Helpers::normalize($matches[5]);
        $res = str_replace($matches[4], '"' . $matches[6] . '"', $res);
        return $res;
    }

    private function deobfuscateDictArrayFuncVars($str, $matches)
    {
        $dictName = $matches[5];

        $res = preg_replace_callback('~chr\((\d+)\)~msi', static function ($match) {
            return '\'' . chr($match[1]) . '\'';
        }, $matches[6]);


        $vars[$matches[2]] = 'base64_decode';
        $vars[$matches[3]] = base64_decode(Helpers::concatStr($matches[4]));

        $res = Helpers::replaceVarsFromArray($vars, $res, true);
        $res = Helpers::concatStringsInContent($res);
        $res = Helpers::replaceVarsFromArray($vars, $res, true, true);

        $res = preg_replace_callback('~str_rot13\([\'"]([^\'"]+)[\'"]\)~msi', static function ($match) {
            return '\'' . str_rot13($match[1]) . '\'';
        }, $res);

        $res = preg_replace_callback('~(?:[\'"][\w=();*/]*[\'"]\.?){2,}~msi', static function ($m) {
            preg_match_all('~(\.?)\s?[\'"]([\w=\+/%&();*]+)[\'"]\s?~msi', $m[0], $concatStrings);
            $strVar = "";
            foreach ($concatStrings[2] as $index => $concatString) {
                if ($concatStrings[1][$index] === '.') {
                    $strVar .= $concatString;
                } else {
                    $strVar = $concatString;
                }
            }

            return '\'' . $strVar . '\'';
        }, $res);

        $arrayVarDict = [];

        preg_match_all('~[\s\'"]*(.*?\]?)[\s\'"]*(,|$)~msi', $res, $arrMatches, PREG_SET_ORDER);

        foreach ($arrMatches as $arrMatch) {
            if ($arrMatch[1] === '') {
                continue;
            }
            $arrayVarDict[] = $arrMatch[1];
        }

        $res = str_replace([$matches[1], $matches[6]], '', $str);
        $res = preg_replace_callback('~(\$\w{1,50})\[(\d+)\]~msi', static function ($match) use ($dictName, $arrayVarDict) {
            if ($dictName === $match[1]) {
                $res = $arrayVarDict[$match[2]] ?? $match[0];
                if (!Helpers::convertToSafeFunc($res) && $res !== 'json_decode' && $res !== 'create_function' && strpos($res, '$') === false) {
                    $res = '"' . $res . '"';
                }
                return $res;
            }
            return $match[0];
        }, $res);

        return $res;
    }

    private function deobfuscateCreateFuncPackStrRot13($str, $matches)
    {
        return pack('H*', str_rot13($matches[2]));
    }

    private function deobfuscateDictVarsCreateFunc($str, $matches)
    {
        $res = $str;
        $dictName = $matches[2];
        $dictVal = stripcslashes($matches[3]);
        $vars = [];

        $res = preg_replace_callback('~(\$\w{1,50})\s?=\s?\w{1,50}\((?:(?:\$\w{1,50}\[\d+\]\s?|[\'"]{2}\s?)[.,]?\s?)+\);~msi',
            function($m) use (&$vars, $dictName, $dictVal) {
            $varName = $m[1];
            $dictResultStr = '';

            preg_match_all('~(\$\w{1,50})\[(\d+)\]~msi', $m[0], $dictVars, PREG_SET_ORDER);
            foreach ($dictVars as $dictVar) {
                if ($dictVar[1] !== $dictName) {
                    continue;
                }

                if ((int)$dictVar[2][0] === 0) {
                    $dictResultStr .= $dictVal[octdec($dictVar[2])] ?? '';
                } else {
                    $dictResultStr .= $dictVal[$dictVar[2]] ?? '';
                }
            }

            $vars[$varName] = $dictResultStr;

            return '';
            }, $str);

        $codeStr = '';
        preg_match_all('~(\$\w{1,50})~msi', $res, $varsMatch, PREG_SET_ORDER);
        foreach ($varsMatch as $var) {
            $codeStr .= $vars[$var[1]] ?? '';
        }

        if (strpos($codeStr, 'eval(base64_decode') !== false) {
            return base64_decode($matches[5]);
        }

        if (strpos($codeStr, 'eval(gzinflate(base64_decode') !== false) {
            return gzinflate(base64_decode($matches[5]));
        }

        return $str;
    }

    private function deobfuscateDecodedFileGetContentsWithFunc($str, $matches)
    {
        $res = str_replace($matches[6], '', $str);

        $resCode = implode(' ', @Helpers::unserialize(base64_decode($matches[5])));

        if (preg_match('~\$\w{1,50}\s?=\s?\'([^\']+)\';\s*\$\w{1,50}\s?=\s?\'([^\']+)\';~msi', $resCode, $configs)) {
            $uid = $configs[1];
            $cfg = $configs[2];

            $resCode = preg_replace_callback('~\$this->\w{1,50}\s?=\s?(@unserialize\(\$this->\w{1,50}\(\w{1,50}::\w{1,50}\(\$this->config\),\s?[\'"]([^\'"]+)[\'"]\)\))~msi',
                static function ($m) use ($uid, $cfg) {
                    $configCodeArray = Helpers::decodeFileGetContentsWithFunc(base64_decode($cfg), $m[2]);
                    $configCodeArray = Helpers::decodeFileGetContentsWithFunc($configCodeArray, $uid);
                    $configCodeArray = @Helpers::unserialize($configCodeArray);
                    $configCodeArray = var_export($configCodeArray, true);

                    return str_replace($m[1], $configCodeArray, $m[0]);
                }, $resCode);
        }

        $res = str_replace($matches[8], $resCode, $res);

        return $res;
    }

    private function deobfuscateCreateFuncVarsCode($str, $matches)
    {
        $vars = Helpers::collectConcatedVars(stripcslashes($matches[1]));

        $tempStr = preg_replace_callback('~(\$\w{1,50})=(.*?);~msi', function ($m) use (&$vars) {
            $var = $this->unwrapFuncs(Helpers::replaceVarsFromArray($vars, $m[2], true, true));

            $vars[$m[1]] = $var;
        }, $matches[2]);

        $func = Helpers::replaceVarsFromArray($vars, $matches[7], true);
        $code = $this->unwrapFuncs("$func'$matches[6]))");

        if (preg_match('~(\$\w{1,50})=array\(((?:\d{1,9},?)+)\);\s*(\$\w{1,50})="";for\((\$\w{1,50})=0;\4<sizeof\(\1\);\4\+=2\){if\(\4%4\){\3\.=substr\(\$\w{1,50},\1\[\4\],\1\[\4\+1\]\);}else{\3\.=\$\w{1,50}\(substr\(\$\w{1,50},\1\[\4\].\1\[\4\+1\]\)\);}};.*?return\s\$\w{1,50};~msi',
                       $code, $codeMatches)) {
            $res      = "";
            $arrayNum = [];

            preg_match_all('~(\d{1,9})~msi', $codeMatches[2], $numbers, PREG_SET_ORDER);
            foreach ($numbers as $number) {
                $arrayNum[] = $number[1];
            }

            for ($i = 0; $i < sizeof($arrayNum); $i += 2) {
                if ($i % 4) {
                    $res .= substr($matches[4], $arrayNum[$i], $arrayNum[$i + 1]);
                } else {
                    $res .= strrev(substr($matches[4], $arrayNum[$i], $arrayNum[$i + 1]));
                }
            };

            $res = $this->unwrapFuncs("$func'$res))");
            if ($res) {
                return $res;
            }
        }

        return $str;
    }

    private function deobfuscatePregConcat($str, $matches)
    {
        return Helpers::normalize($matches[2]);
    }

    private function deobfuscateUndefinedDFunc($str, $matches)
    {
        return 'eval(gzinflate(str_rot13(base64_decode(' . $matches[2] . '))));';
    }

    private function deobfuscateXoredStrings($str, $matches)
    {
        $res = preg_replace_callback('~"([^"]+)"\s*(?:\s*/\*[^\*]+\*/\s*)?\^(?:\s*/\*[^\*]+\*/\s*)?\s*"([^"]+)"~msi', function($m) {
            return '\'' . (stripcslashes($m[1]) ^ stripcslashes($m[2])) . '\'';
        }, $str);

        $res = preg_replace_callback('~\$\{\'(\w+)\'\}~msi', function($m) {
            return '$' . $m[1];
        }, $res);
        Helpers::collectVars($res, '\'', $vars, true);
        $res = Helpers::replaceVarsFromArray($vars, $res, false, false);

        if (preg_match('~(\$\w+)\s*=\s*(\(?\s*gzinflate\s*\(\s*base64_decode\s*)\(\s*\'([^\']+)\'\s*\)\s*\)\s*\)?\s*;\s*\$\w+\s*=\s*@?create_function\(\'([^\']*)\',\s*(?:\1|\'@?eval\(\4\)[^\']+\')\)\s*;\s*@?\$\w+(?:\(\)|\(\1\));~msi', $res, $m)) {
            $res = $this->deobfuscateCreateFuncGzInflateB64($res, $m);
        }
        $res = preg_replace_callback('~/\*[^\*]+\*/~msi', function($m) {
            return '';
        }, $res);
        $res = str_replace('\\\'', '@@slaapos@@', $res);
        preg_match('~\$\{"[^"]+"\^"[^"]+"\}\s*=\s*\'([^\']+)\'\s*;~msi', $res, $m);
        $res = str_replace('@@slaapos@@', '\\\'', $m[1]);
        $res = stripcslashes($res);

        $res = preg_replace_callback('~\(?"([^"]+)"\)?\s*\^\s*\(?"([^"]+)"\)?~msi', function($m) {
            return '\'' . (stripcslashes($m[1]) ^ stripcslashes($m[2])) . '\'';
        }, $res);

        $res = preg_replace_callback('~\$\{\'(\w+)\'\}~msi', function($m) {
            return '$' . $m[1];
        }, $res);

        $replace = function($m) use (&$vars) {
            if (!isset($vars[$m[1]])) {
                return $m[0];
            }
            if (isset($m[2]) && $m[2] !== '') {
                return $vars[$m[1]] . '(';
            }
            return @($vars[$m[1]][0] !== '\'') ? '\'' . $vars[$m[1]] . '\'' : $vars[$m[1]];
        };

        Helpers::collectVars($res, '\'', $vars, true);
        $res = preg_replace_callback('~(\$\w+)\s*(\()?~msi', $replace, $res);
        Helpers::collectFuncVars($res, $vars, true, true);
        $res = preg_replace_callback('~(\$\w+)\s*(\()?~msi', $replace, $res);

        $res = preg_replace('~;+~msi', ';', $res);
        return $res;
    }

    private function deobfuscateCommentWithAlgo($str, $matches)
    {
        return str_replace($matches[1], addcslashes(base64_decode(gzinflate(str_rot13(convert_uudecode(gzinflate(base64_decode($matches[1])))))), '\''), $str);
    }

    private function deobfuscateFileEncryptor($str, $matches)
    {
        return Helpers::replaceBase64Decode($str);
    }

    private function deobfuscateDefinedB64($str, $matches)
    {
        return str_replace([$matches[1], $matches[6], $matches[8]], ['', '', gzinflate(base64_decode($matches[9]))], $str);
    }

    private function deobfuscateB64Xored($str, $matches)
    {
        return base64_decode(Helpers::xorWithKey(base64_decode($matches[4]), $matches[6]));
    }

    private function deobfuscateB64AssignedVarContent($str, $matches)
    {
        return str_replace($matches[4], "'" . (base64_decode($matches[2])) . "'", $matches[3]);
    }

    private function deobfuscateDictVarsWithMath($str, $matches)
    {
        $dictVal = $matches[2];

        $dictStrs = Helpers::calculateMathStr($matches[3]);
        $vars = Helpers::getVarsFromDictionary($dictVal, $dictStrs);
        $vars = Helpers::collectVars($str, '"', $vars);
        $vars = Helpers::collectConcatedVars($str, '"', $vars);

        return $vars[$matches[4]] ?? $str;
    }

    private function deobfuscateClassDecryptedWithKey($str, $matches)
    {
        $key = 'WebKit#58738Educ';

        $data = hex2bin($matches[2]);
        $res = Helpers::decodeClassDecryptedWithKey($data, 32, $key);

        if (strpos($res, 'error_reporting(') !== false) {
            return $res;
        }

        return $str;
    }

    private function deobfuscatePHPkoru($str, $matches)
    {
        $vars[$matches[2]] = str_rot13(base64_decode($matches[3]));
        $vars[$matches[4]] = str_rot13(base64_decode($matches[5]));
        $code = $matches[6];
        while (strpos($code, 'eval') === 0) {
            $code = str_replace(array_keys($vars), array_values($vars), $code);
            $code = $this->unwrapFuncs($code);
        }
        $decoded = '';
        if (preg_match('~openssl_decrypt\(base64_decode\(trim\(\$\w+\[1\]\)\),\s*"([^"]+)",\s*base64_decode\(str_rot13\("([^"]+)"\)\),\s*(\d+),\s*base64_decode\(str_rot13\("([^"]+)"\)\)\)\);~msi', $code, $openssl_data)) {
            $data = base64_decode(trim($matches[8]));
            $algo = $openssl_data[1];
            $passphrase = base64_decode(str_rot13($openssl_data[2]));
            $iv = base64_decode(str_rot13($openssl_data[4]));
            $flags = $openssl_data[3];
            $decoded = openssl_decrypt($data, $algo, $passphrase, $flags, $iv);
            $decoded = str_rot13(base64_decode(str_rot13($decoded)));
        }
        return ' ?> ' .PHP_EOL . $decoded;
    }

    private function deobfuscateJoomlaInject($str, $matches)
    {
        $vars = Helpers::collectVars($matches[0]);
        preg_match('~function\s*\w+\((\$\w+)\)\s*\{\s*(\$\w+)\s*=\s*array\(((?:\'[^\']+\',?)+)\1\);\s*for\((\$\w+)=0;\s*\4<\d+;\s*\4\+\+\)\s*\{\s*for\((\$\w+)=0;\s*\5<strlen\(\2\[\4\]\);\s*\5\+\+\)\s*\2\[\4\]\[\5\]\s*=\s*chr\(ord\(\2\[\4\]\[\5\]\)\s*([\-\+])\s*(\d+)~msi', $this->full_source, $decode_data);
        preg_match_all('~\$this->\w+\(((?|"[^"]+"|\$\w+))\)~msi', $matches[0], $to_decode);
        foreach ($to_decode[1] as &$item) {
            if ($item[0] === '"' && $item[-1] === '"') {
                $item = substr($item, 1, -1);
            }
            $item = str_replace(array_keys($vars), array_values($vars), $item);
            $item = "'" . Helpers::joomlaInjectDecoder($decode_data[3] . $item, $decode_data[6], $decode_data[7]) . "'";
        }
        $res = str_replace($to_decode[0], $to_decode[1], $str);
        return $res;
    }

    private function deobfuscateFwriteB64Content($str, $matches)
    {
        $res = $str;

        $res = str_replace($matches[1], '', $res);
        $replace = base64_decode($matches[3]);

        $res = str_replace($matches[4], "'" . $replace . "'", $res);

        return $res;
    }

    private function deobfuscateB64concatedVars($str, $matches)
    {
        $res = $matches[6];

        $code = "'" . base64_decode($matches[2]) . base64_decode($matches[5]) . "'";

        $res = str_replace($matches[7], $code, $res);

        return $res;
    }

    private function deobfuscateSlashedCreateFunc($str, $matches)
    {
        $func = stripcslashes($matches[2]);

        if (strpos($func, 'create_function') !== false) {
            $code = stripcslashes($matches[5]);
            $code = str_replace($matches[4], $matches[6], $code);

            return $code;
        }

        return $str;
    }

    private function deobfuscateVarDictCreateFunc($str, $matches)
    {
        $res = Helpers::replaceVarsFromDictionary($matches[1], $matches[2], $matches[3]);

        $vars = [];
        $vars = Helpers::collectVars($res, '"', $vars, true);

        $res = Helpers::replaceVarsFromArray($vars, $res);

        return $res;
    }

    private function deobfuscatecallFuncGzB64($str, $matches)
    {
        return gzinflate(base64_decode($matches[1]));
    }

    private function deobfuscateAssertDictVarEval($str, $matches)
    {
        $dict = $matches[2];
        $arr  = [];
        for ($i = 0; $i < 6; $i++) {
            $arr[] = (int)$matches[4 + $i];
        }

        $assertStr = "";
        for ($i = 0; $i < 6; $i++) {
            $temp      = $arr[$i];
            $assertStr .= $dict[$temp];
        }

        $funcs = Helpers::concatStringsInContent(stripcslashes($matches[13]));
        if ($assertStr === 'assert' && strpos($funcs, 'eval(base64_decode(gzinflate(base64_decode(') !== false) {
            return base64_decode(gzinflate(base64_decode($matches[11])));
        }

        $vars               = [];
        $vars[$matches[10]] = $matches[11];
        $vars[$matches[12]] = $assertStr;

        return Helpers::replaceVarsFromArray($vars, $funcs);
    }

    private function deobfuscateB64FuncEvalGz($str, $matches)
    {
        return base64_decode(gzinflate(base64_decode($matches[4])));
    }

    private function deobfuscateB64Gz($str, $matches)
    {
        $result = gzinflate(base64_decode($matches[2]));
        $break = isset($matches[5]) ? '?>' : '';

        return $break . $result;
    }

    private function deobfuscateSubstrEmpty($str, $matches)
    {
        $str = preg_replace_callback('~substr\("([^"]++)",(\d++),(-?\d++)\)~msi', function ($m) {
            return '"' . substr(stripcslashes($m[1]), (int) $m[2], (int) $m[3]) . '"';
        }, $str);
        $str = str_replace(['"."', '"".'], '', $str);
        return $str;
    }

    private function deobfuscateDeltaOrd($str, $matches)
    {
        $str = gzinflate(base64_decode(stripcslashes($matches[4])));
        for($i = 0, $iMax = strlen($str); $i < $iMax; $i++) {
            $str[$i] = chr(ord($str[$i]) + (int) $matches[3]);
        }
        return $str;
    }

    private function deobfuscateOutputBuffer($str, $matches)
    {
        $search = explode(',', str_replace(['\',\'', '\',"', '",\'', '","'], ',', substr($matches[5], 1, -1)));
        $replace = explode(',', str_replace(['\',\'', '\',"', '",\'', '","'], ',', substr($matches[6], 1, -1)));
        $replace = array_map('stripcslashes', $replace);
        $buffer = str_replace($search, $replace, $matches[1] . $matches[9]);
        for ($i = 1, $j = ord($buffer[0]), $iMax = strlen($buffer); $i < $iMax; $i++) {
            $buffer[$i] = chr(ord($buffer[$i]) - $j - $i);
        }
        $buffer[0] = ' ';
        return $buffer;
    }

    private function deobfuscateDoorwayInstaller($str, $matches)
    {
        $vars = [];
        Helpers::collectVars($str, '"', $vars, true);
        $str = preg_replace_callback('~(\$\w+)\((?:"([^"]+)"|(\$\w+))\)~msi', function($m) use ($matches, $vars) {
            if ($m[1] !== $matches[1]) {
                return $m[0];
            }
            if (isset($m[2]) && $m[2] !== '') {
                return '\'' . base64_decode($m[2]) . '\'';
            }
            if (isset($m[3]) && isset($vars[$m[3]])) {
                return '\'' . base64_decode($vars[$m[3]]) . '\'';
            }
        }, $str);
        return $str;
    }

    private function deobfuscateStrReplaceAssert($str, $matches)
    {
        return base64_decode(gzinflate(base64_decode($matches[2])));
    }

    private function deobfuscateAnaLTEAMShell($str, $matches)
    {
        preg_match_all('~\$\{\'GLOBALS\'\}\[\'([^\']+)\'\]=[\'"]([^\'"]+)[\'"];~msi', $str, $m);
        $vars = array_combine($m[1], $m[2]);
        $str = str_replace($m[0], '', $str);
        $str = preg_replace_callback('~\$\{\$\{\'GLOBALS\'\}\[\'([^\']+)\'\]\}~msi', function($m) use ($vars) {
            if (!isset($vars[$m[1]])) {
                return $m[0];
            }
            return '$' . $vars[$m[1]];
        }, $str);
        $str = Helpers::replaceBase64Decode($str);
        $str = preg_replace_callback('~((\$\w+)=\'([^\']+)\';)\$\w+=\$_SERVER\[\'DOCUMENT_ROOT\'\]\.\'/\'\.\'[^\']+\';if\(file_exists\(\$\w+\)\)@?unlink\(\$\w+\);(\$\w+)=(base64_decode\(\2\));~msi', function ($m) {
            $res = str_replace($m[1], '', $m[0]);
            $res = str_replace($m[5], '\'' . base64_decode($m[3]) . '\'', $res);
            return $res;
        }, $str);
        $str = stripcslashes(stripcslashes($str));
        return $str;
    }

    private function deobfuscateZeuraB64Gzinflate($str, $matches)
    {
        return gzinflate(base64_decode($matches[10]));
    }

    private function deobfuscateD5($str, $matches)
    {
        $content = explode(hex2bin($matches[4]), $str)[1];
        $tmp = [];
        for ($i = 0; $i < strlen($content); $i++) {
            $tmp[]=ord($content[$i]) xor $i;
        }
        $content = hex2bin(base64_decode(implode(array_map(hex2bin($matches[8]), $tmp))));
        return $content;
    }

    private function deobfuscateStrReplaceFunc($str, $matches)
    {
        $vars = Helpers::collectFuncVars($matches[3], $vars, false, true);
        $cmd = Helpers::replaceVarsFromArray($vars, $matches[5]);
        if (strpos($cmd, 'create_function') === 0) {
            $cmd = 'eval(' . str_replace('create_function(\'\',', '', $cmd);
        }
        $res = str_replace($matches[6], '\'' . $matches[7] . '\'', $cmd);
        return $res;
    }

    private function deobfuscateArrayMapB64($str, $matches)
    {
        $array = explode('\',\'', substr($matches[2], 1, -1));
        return ' ?>' . base64_decode(str_rot13(implode('', $array))) . '<?php ';
    }

    private function deobfuscatePregReplaceStrReplace($str, $matches)
    {
        return str_replace($matches[1], $matches[2], stripcslashes($matches[3]));
    }

    private function deobfuscateEchoB64($str, $matches)
    {
        return str_replace([$matches[2], $matches[5]], ['\'' . base64_decode($matches[3]) . '\'', '\'' . base64_decode($matches[6]) . '\''], $str);
    }

    private function deobfuscateCreateFuncXored($str, $matches)
    {
        $res = preg_replace_callback('~"([^"]+)"\^"([^"]+)"~msi', function($m) {
            return '\'' . (stripcslashes($m[1]) ^ stripcslashes($m[2])) . '\'';
        }, $str);
        $vars = Helpers::collectVars($res, '\'', $vars, true);
        $res = gzinflate(base64_decode($matches[2]));
        $res = preg_replace('~/\*[^\*]+\*/~msi', '', $res);
        $code = $res;
        if (preg_match('~\$\{"[^"]+"\^"[^"]+"\}\s*=\s*\'((?:\\\\.|[^\'])*+)\';~msi', $code, $matches)) {
            $code = stripcslashes($matches[1]);
            $code = preg_replace_callback('~\(?"([^"]+)"\)?\^\(?"([^"]+)"\)?~msi', function($m) {
                return '\'' . (stripcslashes($m[1]) ^ stripcslashes($m[2])) . '\'';
            }, $code);
            $code = MathCalc::calcRawString($code);
            $vars = [];
            $code = preg_replace_callback('~\$(?:\{\')?(\w+)(?:\'\})?\s*=\s*\'([^\']*)\';+~msi', function($m) use (&$vars) {
                $vars['$' . $m[1] . '('] = $m[2] . '(';
                $vars['$' . $m[1]] = '\'' . $m[2] . '\'';
                return '';
            }, $code);
            $vars['&& !$_0 '] = '&&';
            $vars['if($_0 '] = 'if(';
            krsort($vars);
            $code = str_replace(array_keys($vars), array_values($vars), $code);
        }

        if (preg_match('~(\$\w+)=base64_decode\(\'([^\']+)\'\);;~msi', $code, $m)) {
            $code = str_replace($m[0], '', $code);
            $code = str_replace('eval(' . $m[1] . ');', base64_decode($m[2]), $code);
        }
        $code = preg_replace_callback('~\(?"([^"]+)"\)?\^\(?"([^"]+)"\)?~msi', function($m) {
            return '\'' . (stripcslashes($m[1]) ^ stripcslashes($m[2])) . '\'';
        }, $code);
        $vars = [];
        $code = preg_replace_callback('~(?|\$\{\'(\w+)\'\}\s*=\s*\'(\w+)\'|\$(\w+)\s*=\s*\'(\w+)\');+\s*~msi', function($m) use (&$vars) {
            $vars['$' . $m[1] . '('] = $m[2] . '(';
            $vars['${\'' . $m[1] . '\'}' . '('] = $m[2] . '(';
            $vars['$' . $m[1]] = '\'' . $m[2] . '\'';
            $vars['${\'' . $m[1] . '\'}'] = '\'' . $m[2] . '\'';
            return '';
        }, $code);
        $code = Helpers::replaceVarsFromArray($vars, $code);
        return $code;
    }

    private function deobfuscateCodeLockDecoder($str, $matches)
    {
        $codelock_stub = base64_decode($matches[1]);
        if (isset($matches[2]) && $matches[2] !== '') {
            $codelock_stub = gzinflate($codelock_stub);
            $hangs = 20;
            while (strpos($codelock_stub, 'eval') === 0 && $hangs--) {
                $codelock_stub = $this->UnwrapFuncs($codelock_stub);
            }
        }

        preg_match('~\$codelock_active_key="([^"]*)";~msi', $codelock_stub, $m);
        $codelock_active_key = $m[1];
        preg_match('~\$codelock_usezlib="([^"]*)";~msi', $codelock_stub, $m);
        $codelock_usezlib = $m[1];
        $codelock_key_data = $matches[3];
        if ($codelock_usezlib === "^") {
            $codelock_key_data = base64_decode($codelock_key_data);
            $codelock_key_data = gzinflate($codelock_key_data);
        }
        if (substr($codelock_active_key, 0, 15) !== "codelock_active") {
            $codelock_key_data = Helpers::codelock_dec_int($codelock_key_data, $codelock_active_key);
        } else {
            preg_match('~\$codelock_unlock="([^"]*)";~msi', $codelock_stub, $m);
            $codelock_active_key = $m[1];
            $codelock_key_data = Helpers::codelock_run($codelock_key_data, $codelock_active_key);
        }

        return $codelock_key_data;
    }

    private function deobfuscateEvalGzStrRotB64($str, $matches)
    {
        return gzinflate(str_rot13(base64_decode($matches[2])));
    }

    private function deobfuscateEvalDictArrayConcat($str, $matches)
    {
        $dictVal = '';
        preg_match_all('~[\'"]([^\'"])[\'"]~msi', $matches[2], $m, PREG_SET_ORDER);
        foreach ($m as $char) {
            $dictVal .= $char[1];
        }

        $replacedStr = Helpers::replaceVarsFromDictionary($matches[1], $dictVal, $str);
        $vars = Helpers::collectVars($replacedStr);

        $funcs = Helpers::replaceVarsFromArray($vars, $matches[4]);
        $funcs = Helpers::concatStringsInContent($funcs);
        $funcs = strtolower($funcs);

        if (strpos($funcs, 'eval(str_rot13(gzinflate(str_rot13(gzinflate(base64_decode(') !== false) {
            return str_rot13(gzinflate(str_rot13(gzinflate(base64_decode($matches[6])))));
        }

        return $str;
    }

    private function deobfuscatePregReplaceXored($str, $matches)
    {
        $res = preg_replace_callback('~"([^"]+)"\^"([^"]+)"~msi', function($m) {
            return '\'' . (stripcslashes($m[1]) ^ stripcslashes($m[2])) . '\'';
        }, $str);
        $vars = [];
        $vars = Helpers::collectVars($res, '\"', $vars, true);
        $res = Helpers::replaceVarsFromArray($vars, $res, false, true);
        $res = str_replace('\'.\'', '', $res);
        Helpers::collectVars($res, '\'', $vars, true);
        $res = str_replace(['preg_replace("/' . $matches[2] . '/e",\'\'', '\'\',"' . $matches[2] . '");'], '', $res);
        $res = Helpers::replaceVarsFromArray($vars, $res, false, true);
        return $res;
    }

    private function deobfuscateR4C($str, $matches)
    {
        $vars = [];
        $res = $str;
        $hangs = 20;
        do {
            Helpers::collectConcatedVars($res, '"', $vars, true);
            $res = str_replace('"".$', '$', $res);
            Helpers::collectConcatedVars($res, '\'', $vars, true);
            $res = trim($res);
            $res = Helpers::replaceVarsFromArray($vars, $res, false, true);
            $res = $this->unwrapFuncs($res);
        } while (preg_match('~eval\((?:\w+\()*(?:\$\w+\.?)+\)~', $res) && $hangs--);
        return $res;
    }

    private function deobfuscateBase64EncryptedGz($str, $matches)
    {
        $text       = $matches[1];
        $hash       = $matches[3];
        $key        = 'asdf';
        $key_len    = strlen($key);

        $text       = base64_decode(str_replace("\n", '', $text));
        $text_len   = strlen($text);

        $w = [];
        for ($i = 0; $i < $key_len; ++$i)
        {
            $w[] = $text_len - $key_len - ord($key[$i]);
        }

        for ($i = 0; $i < $text_len; ++$i) {
            $j          = abs($w[$i % $key_len] - $i);
            $x          = $text[$j];
            $text[$j]   = $text[$i];
            $text[$i]   = $x;
        }

        if ($key_len < 10) {
            $key_len *= $key_len & 1 ? 3 : 2;
        }

        if (($text = @gzinflate($text)) && (md5(substr($text, 0, $key_len)) === $hash)) {
            return substr($text, $key_len);
        }

        return '';
    }

    private function deobfuscateBloos3rpent($str, $matches)
    {
        $matches[3] = str_replace('\\\'', '\'', $matches[3]);
        $matches[4] = str_replace('\\\'', '\'', $matches[4]);
        $decoder = strtr($matches[5], $matches[3], $matches[4]);
        preg_match('~\$\w+\s*=\s*\[((?:\'[\da-fx]+\',?)+)\];~msi', $decoder, $funcs);
        $funcs = explode('\',\'', substr($funcs[1], 1, -1));
        $funcs = array_map('hex2bin', $funcs);
        preg_match('~function\s*(\w+)\((\$\w+)\)\s*\{\s*global\s*(\$\w+);\s*return\s*\3\[\d+\]\(\'([^\']+)\',function\(\$\w+\)\s*\{\s*if[^}]+\}return\s*\$\w+;\s*\}\s*else\{\s*return\s*chr[^}]+\}\},\$\w+\);\s*\}\s*function\s*(\w+)\(\$\w+\)\s*\{\s*global\s*\3;\s*eval\(\3\[\d+\]\(\$\w+\)\);\s*\}~msi', $decoder, $tmp);
        $strtr_func = $matches[1];
        $decode_code_func = $tmp[1];
        $eval_func = $tmp[5];
        $arr_funcs = $tmp[3];
        $code = Helpers::replaceVarsFromDictionary($arr_funcs, $funcs, $matches[7], false);
        $hangs = 20;
        while (preg_match('~(\w+)\(\'([^\']+)\'\)~msi', $code) && $hangs--) {
            $code = preg_replace_callback('~(\w+)\(\'([^\']+)\'\)~msi', function ($m) use ($strtr_func, $decode_code_func, $eval_func, $matches) {
                if ($m[1] === $strtr_func) {
                    return '\'' . strtr($m[2], $matches[3], $matches[4]) . '\'';
                }
                if ($m[1] === $decode_code_func) {
                    return '\'' . stripcslashes($m[2]) . '\'';
                }
                if (Helpers::convertToSafeFunc($m[1])) {
                    return '\'' . $m[1]($m[2]) . '\'';
                }
                return $m[0];
            }, $code);
        }
        $code = stripcslashes(substr($code, 1, -2));
        return $code;
    }

    private function deobfuscateDoublePregReplace($str, $matches)
    {
        $matches[2] = substr($matches[2], 1, -1);
        $decoder = @gzinflate(base64_decode(preg_replace('~' . $matches[2] . '~', $matches[3], $matches[4])));
        $res = str_replace($matches[1], $decoder, $str);
        $res = str_replace([$matches[11], $matches[5], $matches[7]], '', $res);
        $res = str_replace('\')))));', '\'))));', $res);
        return $res;
    }

    private function deobfuscateZeura2($str, $matches)
    {
        return 'eval(base64_decode(gzinflate(base64_decode(\'' . $matches[6] . '\'))));';
    }

    private function deobfuscateCreateFuncEscaped($str, $matches)
    {
        return base64_decode($matches[6]);
    }

    private function deobfuscateMaskedDeltaOrd($str, $matches)
    {
        $matches[4] = base64_decode($matches[2]);
        $matches[3] = '-1';
        return $this->deobfuscateDeltaOrd($str, $matches);
    }

    private function deobfuscatedecodeStrMultiForDict($str, $matches)
    {
        $strToDecode = str_replace(['-m ', ' ', PHP_EOL], '', $matches[3]);
        $strToDecode = base64_decode($strToDecode);

        $decodeArray = [];
        for ($i = 0; $i < 256; ++$i) {
            $decodeArray [$i] = $i;
        }

        $index = 0;
        for ($i = 0; $i < 256; ++$i) {
            $index                = ($index + $decodeArray [$i] + ord($matches[6] [$i % 63])) % 256;
            $tempVar              = $decodeArray [$i];
            $decodeArray [$i]     = $decodeArray [$index];
            $decodeArray [$index] = $tempVar;
        }

        $i     = 0;
        $index = 0;
        for ($j = 0; $j < (int)$matches[10]; ++$j) {
            $i                    = ($i + 1) % 256;
            $index                = ($index + $decodeArray [$i]) % 256;
            $tempVar              = $decodeArray [$i];
            $decodeArray [$i]     = $decodeArray [$index];
            $decodeArray [$index] = $tempVar;
            $strToDecode [$j]     = $strToDecode [$j] ^ chr($decodeArray [($decodeArray [$i] + $decodeArray [$index]) % 256]);
        }

        return $strToDecode;
    }

    private function deobfuscateB64ConcatedStrVars($str, $matches)
    {
        $vars        = Helpers::collectVars($str, "'");
        $code        = base64_decode($matches[2]);
        $strToDecode = Helpers::replaceVarsFromArray($vars, $matches[3]);
        $strToDecode = Helpers::concatStringsInContent($strToDecode);
        if (preg_match('~(\$\w{1,50})\s?=\s?base64_decode\(\1\);\s?return\s?@?eval\(\1\);~msi', $code)) {
            return base64_decode($strToDecode);
        }

        return $str;
    }

    private function deobfuscateChrFuncVars($str, $matches)
    {
        $result = preg_replace_callback('~' . $matches[1] . '\(array\(((?:\d+,?)+)\)\)~msi', function ($m) {
            $data = '';
            preg_match_all('~\d+~msi', $m[0], $nums, PREG_SET_ORDER);
            foreach ($nums as $num) {
                $data .= chr($num[0]);
            }
            return "'" . $data . "'";
        }, $str);

        return $result;
    }

    private function deobfuscateConcatVarsFuncs($str, $matches)
    {
        $concatedStr = Helpers::concatStringsInContent($matches[1]);
        $vars = Helpers::collectVars($concatedStr);
        $data = Helpers::concatStringsInContent($matches[2]);
        $data = Helpers::replaceVarsFromArray($vars, $data);

        $code = $this->unwrapFuncs($data);

        if (preg_match('~eval\(rawurldecode\("([^"]+)"~msi', $code, $m)) {
            return rawurldecode($m[1]);
        }

        return $code;
    }

    private function deobfuscateBlackshadow($str, $matches)
    {
        return ($matches[5] . '\'' . $matches[4] . $matches[2] . '\'' . $matches[7]);
    }

    private function deobfuscateGlobalDictVar($str, $matches)
    {
        $str = str_replace($matches[2], '', $str);
        $dict = stripcslashes($matches[4]);
        $str = preg_replace_callback('~\$\w+\[\'\w+\'\]\[(\d+)\]~msi', function ($m) use ($dict) {
            return '\'' . $dict[(int)$m[1]] . '\'';
        }, $str);
        $str = str_replace('\'.\'', '', $str);
        $vars = [];
        $str = preg_replace_callback('~(\$\w+\[\'(\w+)\'\])=(\'[^\']+\'|\$_POST|\$_GET|\$_COOKIE);(?!global)~msi', function($m) use (&$vars) {
            if ($m[3][0] === '\'') {
                $m[3] = substr($m[3], 1, -1);
            }
            $vars[$m[1]] = $m[3];
            $vars['$' . $m[2]] = $m[3];
            return '';
        }, $str);
        $str = Helpers::replaceVarsFromArray($vars, $str);
        return $str;
    }

    private function deobfuscateGarbageVars($str, $matches)
    {
        $str = preg_replace('~"([\w@/:\?>,=\}\.]*)"~msi', '\'\1\'', $str);
        $str = preg_replace_callback('~(?:\'\s*\.\s*(\w+)|(\w+)\s*\.\s*\')~msi', function ($m) {
            if (isset($m[1]) && $m[1] !== '') {
                return '\' . \'' . $m[1] . '\'';
            }
            if (isset($m[2]) && $m[2] !== '') {
                return '\'' . $m[2] . '\' . \'';
            }
        }, $str);

        $str = preg_replace('~\'\s*\.\s*\'~msi', '', $str);
        $str = preg_replace_callback('~(?|\'([^\']+)\'|(\w+))\s*([\^\|\&])\s*(\~)?(?|\'([^\']+)\'|(\w+))~msi', function ($m) {
            if (isset($m[3]) && $m[3] !== '') {
                $m[4] = ~$m[4];
            }
            switch ($m[2]) {
                case '^':
                    return '\'' . ($m[1] ^ $m[4]) . '\'';
                case '|':
                    return '\'' . ($m[1] | $m[4]) . '\'';
                case '&':
                    return '\'' . ($m[1] & $m[4]) . '\'';
            }
        }, $str);

        $vars = Helpers::collectVars($str, '\'', $vars, true);

        $str = preg_replace_callback('~(?|\(\'([^\']+)\'\)|(\$\w+))([\^\&\|])(?|\(\'([^\']+)\'\)|(\$\w+))~msi', function ($m) use ($vars) {
            if ($m[1][0] === '$' && isset($vars[$m[1]])) {
                $m[1] = $vars[$m[1]];
            }
            if ($m[3][0] === '$' && isset($vars[$m[3]])) {
                $m[3] = $vars[$m[3]];
            }
            switch ($m[2]) {
                case '^':
                    return '\'' . ($m[1] ^ $m[3]) . '\'';
                case '|':
                    return '\'' . ($m[1] | $m[3]) . '\'';
                case '&':
                    return '\'' . ($m[1] & $m[3]) . '\'';
            }
        }, $str);

        Helpers::collectVars($str, '\'', $vars, true);
        foreach ($vars as $var => $val) {
            $str = str_replace($var . '(', $val . '(', $str);
            $str = str_replace($var, '\'' . $val . '\'', $str);
        }
        $str = preg_replace('~\'\s*\.\s*\'~msi', '', $str);
        return $str;
    }

    private function deobfuscateChrMinXor($str, $matches)
    {
        $code = (isset($matches[2]) && $matches[2] !== '') ? convert_uudecode(str_replace($matches[5],'', $matches[2])) : base64_decode(strrev($matches[3]));
        $table = [];
        if (isset($matches[5]) && $matches[5] !== '') {
            for($i = 0; $i < 256; ++$i) {
                $table[$i] = $i;
            }
            $j=0;
            for($i = 0; $i < 256; ++$i) {
                $j = ($j + $table[$i] + ord($matches[6][$i % (strlen($matches[6]) - 1)])) % 256;
                $tmp = $table[$i];
                $table[$i] = $table[$j];
                $table[$j] = $tmp;
            }
            $j=0;
            $k=0;
            for($i = 0, $iMax = strlen($code) - 1; $i < $iMax; ++$i) {
                $j = ($j + 1) % 256;
                $k = ($k + $table[$j]) % 256;
                $tmp = $table[$j];
                $table[$j] = $table[$k];
                $table[$k] = $tmp;
                $code[$i] = $code[$i] ^ chr($table[($table[$j] + $table[$k]) % 256]);
            }
        } else {
            for($i = 0, $iMax = strlen($code) - 1; $i < $iMax; ++$i) {
                $code[$i] = $code[$i] ^ $matches[6][$i % (strlen($matches[6]) - 1)];
            }
        }

        return $code;
    }

    private function deobfuscateFakeChop($str, $matches)
    {
        $offset = 2;
        $tmp = base64_decode($matches[2]);
        preg_match('~if\(\$\w+\)(\$\w+)=\$\w+\(\'([^\']+)\',\s*\(\(\$\w+\!=\d+\)\?\'[^\']+\':\'([^\']+)\'\),\1\);\$\w+\+=__LINE__\*1;~msi', $tmp, $m);
        $matches[3] = str_replace($m[2], $m[3], $matches[3]);
        $tmp = base64_decode(substr($matches[3], $offset));
        preg_match('~\w+=\'([^\']+)\';~msi', $tmp, $m);
        $code = base64_decode(substr($m[1], $offset));
        $dicts = [];
        $code = preg_replace_callback('~\$GLOBALS\[([^\]]+)\]=explode\("([^"]+)",\s*"([^"]+)"\);~msi', function ($m) use (&$dicts) {
           $dicts[$m[1]] = explode($m[2], $m[3]);
           return '';
        }, $code);
        $code = preg_replace_callback('~\$GLOBALS\[([^\]]+)\]=explode\(pack\(\$GLOBALS\[([^\]]+)\]\[(\d+)\],\$GLOBALS\[([^\]]+)\]\[(\d+)\]\),pack\(\$GLOBALS\[([^\]]+)\]\[(\d+)\],\$GLOBALS\[([^\]]+)\]\[(\d+)\]\)\);~msi', function ($m) use (&$dicts) {
            $dicts[$m[1]] = explode(pack($dicts[$m[2]][$m[3]], $dicts[$m[4]][$m[5]]), pack($dicts[$m[6]][$m[7]], $dicts[$m[8]][$m[9]]));
            return '';
        }, $code);
        $code = preg_replace_callback('~\$GLOBALS\[([^\]]+)\]\[([xa-f\d]+)\](\()?~msi', function ($m) use ($dicts) {
            $offset = $m[2][1] === 'x' ? hexdec($m[2]) : ($m[2][0] === '0' ? octdec($m[2]) : $m[2]);
            return (isset($m[3]) && $m[3] !== '') ? $dicts[$m[1]][$offset] . '(' : '\'' . $dicts[$m[1]][$offset] . '\'';
        }, $code);
        $code = preg_replace_callback('~pack\(\'H\*\',\'([\da-f]+)\'\)~msi', function ($m) {
            return '\'' . pack('H*', $m[1]) . '\'';
        }, $code);
        preg_match('~\$[^=]+=array\(array\((\'[^\)]+)\)\);~msi', $code, $m);
        $m[1] = substr($m[1], 1, -1);
        $m[1] = str_replace('\',\'', '', $m[1]);
        $code = base64_decode(str_rot13($m[1]));
        return $code;
    }

    private function deobfuscateAssertUrldecode($str, $matches)
    {
        return $this->deobfuscateEval(stripcslashes($matches[2]), []);
    }

    private function deobfuscateImplodeB64Gz($str, $matches)
    {
        $b64str = str_replace('\',\'', '', $matches[2]);
        $code = gzuncompress(base64_decode($b64str));
        $code = Helpers::normalize(MathCalc::calcRawString($code));
        $arr = [];
        $func = '';
        $code = preg_replace_callback('~if\(!function_exists\(\'(\w+)\'\)\)\{function\s*\1\((\$\w+)\)\s*\{(\$\w+)=array\(([^)]+)\);return\s*base64_decode\(\3\[\2\]\);\}~msi', function ($m) use (&$arr, &$func) {
            $arr = explode('\',\'', substr($m[4], 1, -1));
            $func = $m[1];
            return '';
        }, $code);
        foreach($arr as $i => $data) {
            $code = str_replace($func . '(' . $i . ')', '\'' . base64_decode($data) . '\'', $code);
        }
        return $code;
    }

    private function deobfuscateEvalStrReplace($str, $matches)
    {
        return base64_decode(str_replace($matches[8], '', $matches[2]));
    }

    private function deobfuscateX12($str, $matches)
    {
        $vars = Helpers::collectVars($matches[1]);
        $matches[2] = Helpers::replaceVarsFromArray($vars, $matches[2], false, true);
        $matches[2] = Helpers::normalize($matches[2]);
        $funcs = Helpers::collectVars($matches[2], '\'');
        $matches[3] = Helpers::replaceVarsFromArray($funcs, $matches[3]);
        return $this->deobfuscateEval($matches[3], []);
    }

    private function deobfuscateWpNightmare($str, $matches)
    {
        return gzinflate(base64_decode($matches[8]));
    }

    private function deobfuscateXorGzUncompress($str, $matches)
    {
        $vars = Helpers::collectVars($matches[1], '\'');
        $code = array_pop($vars);
        $code = base64_decode($code);
        $code = Helpers::xorWithKey($code, $matches[10]);
        return gzuncompress($code);
    }

    private function deobfuscateEvalSubstr($str, $matches)
    {
        return base64_decode(substr(strrev($matches[2]), (int)$matches[3],(int)$matches[4]));
    }

    private function deobfuscateEvalStrrev($str, $matches)
    {
        $code = base64_decode(strrev($matches[2]));
        return $code;
    }

    private function deobfuscateStrRot13ConvertUUDecode($str, $matches)
    {
        $decode = str_rot13($matches[2]);
        $decode = stripcslashes($decode);
        $decode = preg_replace(['~eval\(convert_uudecode\(\s*\'~msi', '~\'\)\);~msi'], '', $decode);
        $decode = stripcslashes($decode);
        $decode = convert_uudecode($decode);
        $decode = $this->deobfuscateEval($decode, []);
        if (preg_match('~eval\(strrev\(\s*\';\)\)\s*\\\\\'eval\(convert_uudecode\(\s*\\\\(["\'])((?:[^;]+;)+[^\']+)\\\\\'\\\\\\\\\)\);\\\\\1\s*\(verrts\(lave\'\s*\)\);~msi', $decode, $m)) {
            $decode = preg_replace_callback('~(?:(\\\\\\\\\\\\\\\\\\\\\')|(\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\)|(\\\\\\\\))~m', function($g) {
                if (isset($g[1]) && $g[1] !== '') {
                    return '\'';
                }
                if (isset($g[2]) && $g[2] !== '') {
                    return '\\';
                }
                if (isset($g[3]) && $g[3] !== '') {
                    return '';
                }
            }, $m[2]);
            $decode = convert_uudecode($decode);
        }
        return $decode;
    }

    private function deobfuscateCreateFuncHex($str, $matches)
    {
        $decode = stripcslashes($matches[5]);
        $decode = str_replace($matches[4], '\'' . $matches[6] . '\'', $decode);
        return $decode;
    }

    private function deobfuscatePregB64Strrev($str, $matches)
    {
        return $this->deobfuscateEvalStrrev($str, $matches);
    }

    private function deobfuscatePregB64FuncImgStr($str, $matches)
    {
        $decodedStr = base64_decode($matches[13]);

        if (preg_match('~<img src="data:image/png;(.*)">~msi', $decodedStr, $foundB64) !== false) {
            $decodedStr = str_replace(
                [base64_decode($matches[4]), base64_decode($matches[5])],
                [base64_decode($matches[6]), base64_decode($matches[7])],
                $foundB64[1]
            );
            $decodedStr = gzinflate(base64_decode($decodedStr));

            return str_replace($matches[11], $decodedStr, $str);
        }

        return $str;
    }

    private function deobfuscateUtfCharVarsFuncEval($str, $matches)
    {
        $vars = [];
        $res = $str;
        $globalVarName = $matches[1];
        $funcName = $matches[2];

        $res = Helpers::utfCharVarsFuncEvalCodeDecoder($res, $vars, $globalVarName, $funcName);

        for ($i = 0; $i < 10; $i++) {
            $found = false;

            if (preg_match('~eval\(?\s*@?\s*(?:base64_decode\s*\(|pack\s*\(\'H\*\',|convert_uudecode\s*\(|htmlspecialchars_decode\s*\(|gzdecode\s*\(|stripslashes\s*\(|gzinflate\s*\(|strrev\s*\(|str_rot13\s*\(|gzuncompress\s*\(|urldecode\s*\(|rawurldecode\s*\(|unserialize\s*\(|eval\s*\(|hex2bin\()+.*?[^\'");]+(\s*[\'"\)]+)+\s*;~msi', $res, $matches)) {
                $unWrapped = $this->unwrapFuncs($matches[0]);
                $res = str_replace($matches[0], $unWrapped, $res);
                $found = true;
            } else if (preg_match('~eval\('. $funcName . '\(base64_decode\(\'([^\']+)\'\)+;~msi', $res, $funcMatch)) {
                $code = base64_decode($funcMatch[1]);
                $code = Helpers::utfCharVarsFuncEvalVarDecoder($code);
                $res = str_replace($funcMatch[0], $code, $res);
                $found = true;
            }
            if ($found) {
                $res = Helpers::utfCharVarsFuncEvalCodeDecoder($res, $vars, $globalVarName, $funcName);
            } else {
                break;
            }
        }
        $res = Helpers::replaceBase64Decode($res);

        return $res;
    }

    private function deobfuscateManyVarFuncCreateFuncWrap($str, $matches)
    {
        $createFuncCode = hex2bin(pack('H*', $matches[8]));
        if (strpos($createFuncCode, 'eval($') !== false) {
            return gzinflate(hex2bin(pack('H*', $matches[9])));
        }

        return $str;
    }

    /*************************************************************************************************************/
    /*                                          JS deobfuscators                                                 */
    /*************************************************************************************************************/

    private function deobfuscateJS_fromCharCode($str, $matches)
    {
        $result = '';
        $chars = explode(',', $matches[4]);
        foreach ($chars as $char) {
            $result .= chr((int)trim($char));
        }
        if (!(isset($matches[3]) && $matches[3] === 'eval(')) {
            $result = '\'' . $result . '\'';
        }
        if (isset($matches[1]) && $matches[1] !== '') {
            $result = $matches[1] . $result;
        }
        if (isset($matches[5]) && $matches[5] !== '') {
            $result = $result . $matches[5];
        }

        return $result;
    }

    private function deobfuscateJS_unescapeContentFuncWrapped($str, $matches)
    {
        $result = '';

        $functionCode = urldecode($matches[1]);
        $functionName = urldecode($matches[2]);
        $strDecoded = $matches[3];

        if (preg_match('~function\s?(\w{1,50})\(\w{1,50}\)\s{0,50}{\s{0,50}var\s?\w{1,50}\s?=\s?[\'"]{2};\s{0,50}var\s?\w{1,50}\s?=\s?\w{1,50}\.split\("(\d+)"\);\s{0,50}\w{1,50}\s?=\s?unescape\(\w{1,50}\[0\]\);\s{0,50}\w{1,50}\s?=\s?unescape\(\w{1,50}\[1\]\s?\+\s?"(\d{1,50})"\);\s{0,50}for\(\s?var\s?\w{1,50}\s?=\s?0;\s?\w{1,50}\s?<\s?\w{1,50}\.length;\s?\w{1,50}\+\+\)\s?{\s{0,50}\w{1,50}\s?\+=\s?String\.fromCharCode\(\(parseInt\(\w{1,50}\.charAt\(\w{1,50}%\w{1,50}\.length\)\)\^\w{1,50}\.charCodeAt\(\w{1,50}\)\)\+-2\);\s{0,50}}\s{0,50}return\s\w{1,50};\s{0,50}}~msi',
                $functionCode, $match) && strpos($functionName, $match[1])) {
            $tmp = explode((string)$match[2], $strDecoded);
            $s = urldecode($tmp[0]);
            $k = urldecode($tmp[1] . (string)$match[3]);
            $kLen = strlen($k);
            $sLen = strlen($s);

            for ($i = 0; $i < $sLen; $i++) {
                $result .= chr(((int)($k[$i % $kLen]) ^ ord($s[$i])) - 2);
            }
        } else {
            $result = $matches[3];
            $result = str_replace([$matches[1], $matches[2]], [$functionCode, $functionCode], $result);
        }

        return $result;
    }

    private function deobfuscateJS_ObfuscatorIO($str, $matches)
    {
        $detectPattern = '~((?![^_a-zA-Z$])[\w$]*)\(-?(\'|")(0x[a-f\d]+|\\x30\\x78[\\xa-f\d]+)\2(\s*,\s*(\'|").+?\5)?\)~msi';
        preg_match_all($detectPattern, $str, $detectMatch);
        $detectMatch = array_unique($detectMatch[1]);
        if (count($detectMatch) !== 1) {
            return $str;
        }

        preg_match('~\b(?:var|const|let)\s+' . $detectMatch[0] . '\s*=\s*function\s*\(.*?\)\s*~msi', $str, $index, PREG_OFFSET_CAPTURE);
        $index = $index[0][1];

        $bo = 0;
        $bc = 0;
        $strSize = strlen($str);
        $mainCode = '';
        while ($index < $strSize) {
            if ($str[$index] === '{') {
                $bo++;
            }
            if ($str[$index] === '}') {
                $bc++;
            }
            if ($bc === $bo && $bo !== 0) {
                $mainCode = substr($str, $index + 2);
                break;
            }
            $index++;
        }
        $array = explode('\',\'', substr($matches[2], 1, -1));

        $shuffle = hexdec($matches[3]);
        while ($shuffle--) {
            $array[] = array_shift($array);
        }
        $mainCode = preg_replace_callback('~((?![^_a-zA-Z$])[\w$]*)\(-?(\'|")(0x[a-f\d]+|\\x30\\x78[\\xa-f\d]+)\2(\s*,\s*(\'|")(.+?)\5)?\)~msi', function ($m) use ($array) {
            return '\'' . Helpers::deobfuscatorIO_string($array[hexdec($m[3])], $m[6]) . '\'';
        }, $mainCode);
        return Helpers::normalize($mainCode);
    }

    private function deobfuscateJS_documentWriteUnescapedStr($str, $matches)
    {
        if (strpos($matches[1], '\u00') !== false) {
            $matches[1] = str_replace('\u00', '%', $matches[1]);
        }
        return urldecode($matches[1]);
    }

    private function deobfuscateJS_deanPacker($str, $matches)
    {
        $payload = $matches[1];
        // Words
        $symtab = explode('|', $matches[4]);
        // Radix
        $radix = (int)$matches[2];
        // Words Count
        $count = (int)$matches[3];

        if ($count !== count($symtab)) {
            return $str; // Malformed p.a.c.k.e.r symtab !
        }

        $array = [];

        while ($count--) {
            $tmp = Helpers::jsPackerUnbaser($count, $radix);
            $array[$tmp] = (isset($symtab[$count]) && $symtab[$count] !== '') ? $symtab[$count] : $tmp;
        }

        $result = preg_replace_callback('~\b\w+\b~', function($m) use ($array) {
            return $array[$m[0]];
        }, $payload);
        $result = str_replace('\\', '', $result);
        if (preg_match('~function\(\)\{var\s*(\w+)=\{([\$\w]+):\'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\+/=\',\w+:function\(\w+\){var\s*\w+=\'\',\w,\w,\w,\w,\w,\w,\w,\w=0;\w=\1\.[\w\$]+\(\w\);while\(\w<\w\.length\)\{[^{]+\{\w=\w=64\}else[^{]+\{\w=64\};[^}]+};return\s*\w},(\w+):function\(\w\)\{var\s*\w+=\'\',\w,\w,\w,\w,\w,\w,\w,\w=0;\w=\w\.replace\(/\[\^A\-Za\-z0\-9\+/=\]/g,\'\'\);while\(\w<\w\.length\){\w=this\.\2\.indexOf\(\w\.charAt\(\w\+\+\)\);~msi', $result, $m)) {
            $class = $m[1];
            $b64_func = $m[3];
            $result = preg_replace_callback('~(?:var\s(\w+)=\'([^\']+)\';\1=(\w+\.\w+)\(\1\)|(\w+\.\w+)\(\'([^\']+)\'\))~msi', function($m) use ($class, $b64_func) {
                if ((isset($m[4]) && $m[4] !== '' && $m[4] !== $class . '.' . $b64_func)
                 || (isset($m[3]) && $m[3] !== '' && $m[3] !== $class . '.' . $b64_func)
                ) {
                    return $m[0];
                }
                if (isset($m[4]) && $m[4] !== '') {
                    return '\'' . base64_decode($m[5]) . '\'';
                }
                if (isset($m[3]) && $m[3] !== '') {
                    return 'var ' . $m[1] . '=\'' . base64_decode($m[2]) . '\'';
                }
            }, $result);
            $result = preg_replace_callback('~\w+=\[((?:\'[^\']+\',?)+)\]~msi', function($m) {
                $arr = explode('\',\'', substr($m[1], 1, -1));
                $arr = array_map('base64_decode', $arr);
                return str_replace($m[1], '\'' . implode('\',\'', $arr) . '\'', $m[0]);
            }, $result);

        }
        return $result;
    }

    private function deobfuscateJS_objectDecode($str, $matches)
    {
        $ciphered = explode('+', $matches[9]);
        $chars = explode('\',\'', substr($matches[13], 1, -1));
        $count = (int)$matches[8];
        $arr = [];
        for ($i = 0; $i < $count; $i++) {
            $arr[Helpers::jsObjectDecodeIndexToString($i)] = $ciphered[$i][0] !== ';' ? '\'' . Helpers::jsObjectStringDecoder($matches[11], $chars, $ciphered[$i]) . '\'' : (float)substr($ciphered[$i], 1);
        }
        $ret = preg_replace_callback('~\$\.\b(\w+)\b~', function($m) use ($arr) {
            if (!isset($arr[$m[1]])) {
                return $m[0];
            }
            return $arr[$m[1]];
        }, $matches[2]);

        return $ret;
    }

    /*************************************************************************************************************/
    /*                                          PYTHON deobfuscators                                             */
    /*************************************************************************************************************/

    private function deobfuscatePY_evalCompileStr($str, $matches)
    {
        return gzuncompress(base64_decode($matches[1]));
    }
}


class ContentObject
{
    private $content = false;
    private $normalized_file_content = false;
    private $unescaped_normalized = false;
    private $unescaped = false;
    private $decoded_converted = false;
    private $decoded_file_content = false;
    private $normalized_decoded = false;
    private $decoded_fragments = false;
    private $decoded_fragments_string = false;
    private $norm_decoded_fragments = false;
    private $norm_decoded_fragments_string = false;
    private $norm_decoded_file_content = false;
    private $converted_file_content = false;
    private $converted_decoded = false;
    private $strip_decoded = false;
    private $type = '';

    private $deobfuscate = false;
    private $unescape = false;


    public function __construct($content, $deobfuscate = false, $unescape = false)
    {
        $this->content = $content;
        $this->deobfuscate = $deobfuscate;
        $this->unescape = $unescape;
    }

    public function getType()
    {
        return $this->type;
    }

    public function getContent()
    {
        if ($this->content !== false) {
            return $this->content;
        }
    }

    public function getUnescaped()
    {
        if (!$this->unescape) {
            $this->unescaped = '';
            $this->unescaped_normalized = '';
        }
        if ($this->unescaped !== false) {
            return $this->unescaped;
        }
        $this->unescaped = Normalization::unescape($this->getContent());
        return $this->unescaped;
    }

    public function getNormalized()
    {
        if ($this->normalized_file_content !== false) {
            return $this->normalized_file_content;
        }
        $this->normalized_file_content = Normalization::strip_whitespace($this->getContent());
        $this->normalized_file_content = Normalization::normalize($this->normalized_file_content);
        return $this->normalized_file_content;
    }

    public function getUnescapedNormalized()
    {
        if (!$this->unescape) {
            $this->unescaped = '';
            $this->unescaped_normalized = '';
        }
        if ($this->unescaped_normalized !== false) {
            return $this->unescaped_normalized;
        }
        $this->unescaped_normalized = Normalization::strip_whitespace(Normalization::unescape($this->getContent()));
        $this->unescaped_normalized = Normalization::normalize($this->unescaped_normalized);
        return $this->unescaped_normalized;
    }

    public function getDecodedFileContent()
    {
        if (!$this->deobfuscate) {
            $this->decoded_file_content = '';
            $this->decoded_fragments = [];
            $this->decoded_fragments_string = '';
            $this->norm_decoded_file_content = '';
        }
        if ($this->decoded_file_content !== false) {
            return $this->decoded_file_content;
        }
        $deobf_obj = new Deobfuscator($this->getContent());
        $deobf_type = $deobf_obj->getObfuscateType($this->getContent());
        if ($deobf_type != '') {
            $this->decoded_file_content = $deobf_obj->deobfuscate();
            $this->decoded_fragments = $deobf_obj->getFragments();
            $this->decoded_fragments_string = is_array($this->decoded_fragments) ? Normalization::normalize(implode($this->decoded_fragments)) : '';
            $this->norm_decoded_file_content = Normalization::normalize($this->decoded_file_content);
        } else {
            $this->decoded_file_content = '';
            $this->decoded_fragments = [];
            $this->decoded_fragments_string = '';
            $this->norm_decoded_file_content = '';
        }
        return $this->decoded_file_content;
    }

    public function getDecodedNormalizedContent()
    {
        if (!$this->deobfuscate) {
            $this->normalized_decoded = '';
            $this->norm_decoded_fragments = [];
            $this->norm_decoded_fragments_string = '';
        }
        if ($this->normalized_decoded !== false) {
            return $this->normalized_decoded;
        }
        $deobf_obj = new Deobfuscator($this->getNormalized());
        $deobf_type = $deobf_obj->getObfuscateType($this->getNormalized());
        if ($deobf_type != '') {
            $this->normalized_decoded = $deobf_obj->deobfuscate();
            $this->norm_decoded_fragments = $deobf_obj->getFragments();
            $this->norm_decoded_fragments_string = is_array($this->norm_decoded_fragments) ? Normalization::normalize(implode($this->norm_decoded_fragments)) : '';
        } else {
            $this->normalized_decoded = '';
            $this->norm_decoded_fragments = [];
            $this->norm_decoded_fragments_string = '';
        }
        return $this->normalized_decoded;
    }

    public function getDecodedFragments()
    {
        if ($this->decoded_fragments !== false) {
            return $this->decoded_fragments;
        }
        $this->getDecodedFileContent();
        return $this->decoded_fragments;
    }

    public function getDecodedFragmentsString()
    {
        if ($this->decoded_fragments_string !== false) {
            return $this->decoded_fragments_string;
        }
        $this->getDecodedFileContent();
        return $this->decoded_fragments_string;
    }

    public function getNormDecodedFragments()
    {
        if ($this->norm_decoded_fragments !== false) {
            return $this->norm_decoded_fragments;
        }
        $this->getDecodedNormalizedContent();
        return $this->norm_decoded_fragments;
    }

    public function getNormDecodedFragmentsString()
    {
        if ($this->norm_decoded_fragments_string !== false) {
            return $this->norm_decoded_fragments_string;
        }
        $this->getDecodedNormalizedContent();
        return $this->norm_decoded_fragments_string;
    }

    public function getNormDecodedFileContent()
    {
        if ($this->norm_decoded_file_content !== false) {
            return $this->norm_decoded_file_content;
        }
        $this->getDecodedNormalizedContent();
        return $this->norm_decoded_file_content;
    }

    public function getConvertedContent()
    {
        if ($this->converted_file_content !== false) {
            return $this->converted_file_content;
        }
        $this->converted_file_content = '';
        $l_UnicodeContent = Encoding::detectUTFEncoding($this->getContent());
        if ($l_UnicodeContent !== false) {
            if (Encoding::iconvSupported()) {
                $this->converted_file_content = Encoding::convertToCp1251($l_UnicodeContent, $this->getContent());
            }
        }
        $this->converted_file_content = Normalization::normalize($this->converted_file_content);
        return $this->converted_file_content;
    }

    public function getConvertedDecodedContent()
    {
        if (!$this->deobfuscate) {
            $this->converted_decoded = '';
        }
        if ($this->converted_decoded !== false) {
            return $this->converted_decoded;
        }
        $strip = Normalization::strip_whitespace($this->getConvertedContent());
        $deobf_obj = new Deobfuscator($strip, $this->getConvertedContent());
        $deobf_type = $deobf_obj->getObfuscateType($strip);
        if ($deobf_type != '') {
            $this->converted_decoded = $deobf_obj->deobfuscate();
        } else {
            $this->converted_decoded = '';
        }
        $this->converted_decoded = Normalization::normalize($this->converted_decoded);
        return $this->converted_decoded;
    }

    public function getStripDecodedContent()
    {
        if (!$this->deobfuscate) {
            $this->strip_decoded = '';
        }
        if ($this->strip_decoded !== false) {
            return $this->strip_decoded;
        }
        $strip = Normalization::strip_whitespace($this->getContent());
        $deobf_obj = new Deobfuscator($strip, $this->getContent());
        $deobf_type = $deobf_obj->getObfuscateType($strip);
        $this->type = $deobf_type;
        if ($deobf_type != '') {
            $this->strip_decoded = $deobf_obj->deobfuscate();
        } else {
            $this->strip_decoded = '';
        }
        $this->strip_decoded = Normalization::normalize($this->strip_decoded);
        return $this->strip_decoded;
    }
}

class CleanUnit
{

    const URL_GRAB = '~<(script|iframe|object|embed|img|a)\s*.{0,300}?((?:https?:)?\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+\~#=]{2,256}\.[a-z]{2,4}\b(?:[-a-zA-Z0-9@:%_\+.\~#?&/=]*)).{0,300}?</\1>~msi';

    public static function CleanContent(&$file_content, $clean_db, $deobfuscate = false, $unescape = false, $signature_converter = null, $precheck = null, $src_file = null, $demapper = false, &$matched_not_cleaned = null)
    {
        $result = false;
        $content_orig = new ContentObject($file_content, $deobfuscate, $unescape);
        $content = new ContentObject($file_content, $deobfuscate, $unescape);
        $terminate  = false;
        $prev_id = '';

        if (isset($src_file) && $demapper && $deobfuscate) {
            if (self::checkFalsePositives($src_file, $content->getStripDecodedContent(), $content->getType(), $demapper)) {
                return $result;
            }
        }

        foreach ($clean_db->getDB() as $rec_index => $rec) {
            if ($terminate) {
                break;
            }

            if (is_callable($precheck) && !$precheck($rec['mask_type'])) {
                continue;
            }

            switch ($rec['sig_type']) {
                case 4: // normalize first line
                case 5: // match deobfuscated content and replace related obfuscated part
                case 0: // simple match
                    if (isset($signature_converter)) {
                        $inj_sign = $signature_converter->getCutSignature($rec_index);
                    }
                    if (!(isset($inj_sign) && $inj_sign)) {
                        $inj_sign = $rec['sig_match'];
                    }
                    $nohang = 20; // maximum 20 iterations
                    $condition_num = 0; // for debug
                    while (
                        (
                            (
                                preg_match('~' . $rec['sig_match'] . '~smi', $content->getContent(), $fnd, PREG_OFFSET_CAPTURE)
                                && $condition_num = 1
                            )
                            || (
                                ($normalized_file_content = $content->getNormalized())
                                && $normalized_file_content != ''
                                && preg_match('~' . $rec['sig_match'] . '~smi', $normalized_file_content, $norm_fnd, PREG_OFFSET_CAPTURE)
                                && $condition_num = 3
                            )
                            || (
                                ($decoded_fragments_string = $content->getDecodedFragmentsString())
                                && $decoded_fragments_string != ''
                                && preg_match('~' . $inj_sign . '~smi', $decoded_fragments_string, $dec_fnd, PREG_OFFSET_CAPTURE)
                                && $condition_num = 2
                            )
                            || (
                                ($norm_decoded_fragments_string = $content->getNormDecodedFragmentsString())
                                && $norm_decoded_fragments_string != ''
                                && preg_match('~' . $inj_sign . '~smi', $norm_decoded_fragments_string, $norm_dec_fnd, PREG_OFFSET_CAPTURE)
                                && $condition_num = 4
                            )
                            || (
                                ($unescaped_norm = $content->getUnescapedNormalized())
                                && $unescaped_norm != ''
                                && preg_match('~' . $rec['sig_match'] . '~smi', $unescaped_norm, $unescaped_norm_fnd, PREG_OFFSET_CAPTURE)
                                && $condition_num = 5
                            )
                            || (
                                ($unescaped = $content->getUnescaped())
                                && $unescaped != ''
                                && preg_match('~' . $rec['sig_match'] . '~smi', $unescaped, $unescaped_fnd, PREG_OFFSET_CAPTURE)
                                && $condition_num = 6
                            )
                        )
                        && ($nohang-- > 0)
                    ) {
                        if (trim($rec['sig_replace']) === '<?php') {
                            $rec['sig_replace'] = '<?php ';
                        }

                        $normal_fnd = isset($norm_fnd[0][0]) ? $norm_fnd[0][0] : false;
                        $unescaped_normal_fnd = isset($unescaped_norm_fnd[0][0]) ? $unescaped_norm_fnd[0][0] : false;
                        $un_fnd = isset($unescaped_fnd[0][0]) ? $unescaped_fnd[0][0] : false;

                        if (!empty($normal_fnd)) {
                            $pos = Normalization::string_pos($file_content, $normal_fnd);
                            if ($pos !== false) {
                                $replace = self::getReplaceFromRegExp($rec['sig_replace'], $norm_fnd);
                                $file_content = self::replaceString($file_content, $replace, $pos[0], $pos[1] - $pos[0] + 1);
                            }
                        }

                        if (!empty($unescaped_normal_fnd)) {
                            $pos = Normalization::string_pos($file_content, $unescaped_normal_fnd, true);
                            if ($pos !== false) {
                                $replace = self::getReplaceFromRegExp($rec['sig_replace'], $unescaped_norm_fnd);
                                $ser = false;
                                $file_content = self::replaceString($file_content, $replace, $pos[0], $pos[1] - $pos[0] + 1, $ser, true);
                            }
                        }

                        if (!empty($un_fnd)) {
                            $pos = Normalization::string_pos($file_content, $un_fnd, true);
                            if ($pos !== false) {
                                $matched_not_cleaned = false;
                                $replace = self::getReplaceFromRegExp($rec['sig_replace'], $unescaped_fnd);
                                $ser = false;
                                $file_content = self::replaceString($file_content, $replace, $pos[0], $pos[1] - $pos[0] + 1, $ser, true);
                            }
                        }

                        if (isset($fnd) && $fnd) {
                            $replace = self::getReplaceFromRegExp($rec['sig_replace'], $fnd);
                            $file_content = self::replaceString($file_content, $replace, $fnd[0][1], strlen($fnd[0][0]));
                        }
                        $decoded_fragments = $content->getDecodedFragments();
                        if (isset($dec_fnd) && $dec_fnd && !empty($decoded_fragments)) {
                            foreach ($decoded_fragments as $obfuscated => $deobfuscated) {
                                if (preg_match('~' . $inj_sign  . '~smi', Normalization::normalize($deobfuscated))) {
                                    $pos = Normalization::string_pos($file_content, $obfuscated);
                                    if ($pos !== false) {
                                        $replace = self::getReplaceFromRegExp($rec['sig_replace'], $dec_fnd);
                                        $file_content = self::replaceString($file_content, $replace, $pos[0], $pos[1] - $pos[0] + 1);
                                    }
                                }
                            }
                        }

                        $norm_decoded_fragments = $content->getNormDecodedFragments();
                        if (isset($norm_dec_fnd) && $norm_dec_fnd && !empty($norm_decoded_fragments)) {
                            foreach ($norm_decoded_fragments as $obfuscated => $deobfuscated) {
                                if (preg_match('~' . $inj_sign  . '~smi', Normalization::normalize($deobfuscated))) {
                                    $pos = Normalization::string_pos($file_content, $obfuscated);
                                    if ($pos !== false) {
                                        $replace = self::getReplaceFromRegExp($rec['sig_replace'], $norm_dec_fnd);
                                        $file_content = self::replaceString($file_content, $replace, $pos[0], $pos[1] - $pos[0] + 1);
                                    }
                                }
                            }
                        }

                        $file_content = preg_replace('~<\?php\s+\?>~smi', '', $file_content);
                        $file_content = preg_replace('~<\?\s+\?>~smi', '', $file_content);
                        $file_content = preg_replace('~\A\s*<\?php\s*\Z~smi', '', $file_content);
                        $file_content = preg_replace('~\A\s*<\?\s*\Z~smi', '', $file_content);
                        $file_content = preg_replace('~\A\s*\?>\s*\Z~smi', '', $file_content);
                        $file_content = preg_replace('~\A\s+<\?~smi', '<?', $file_content);
                        $file_content = preg_replace('~\A\xEF\xBB\xBF\s*\Z~smi', '', $file_content);

                        $empty = (trim($file_content) == '');

                        if ($prev_id !== $rec['id']) {
                            $result[] = ['sig_type' => $rec['sig_type'], 'id' => $rec['id'], 'empty' => $empty];
                        }

                        $matched_not_cleaned = $content_orig->getContent() === $file_content;

                        if ($empty) {
                            $terminate = true;
                        }

                        if ($file_content !== $content->getContent()) {
                            unset($content);
                            $content = new ContentObject($file_content, $deobfuscate, $unescape);
                        }
                        $prev_id = $rec['id'];
                    } // end of while


                    break;
                case 1: // match signature and delete file
                    $condition_num = 0; // for debug
                    if (
                        (
                            $rec['sig_match'] == '-'
                            && $condition_num = 1
                        )
                        || (
                            preg_match('~' . $rec['sig_match'] . '~smi', $content->getContent(), $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 2
                        )
                        || (
                            ($decoded_file_content = $content->getNormDecodedFileContent())
                            && $decoded_file_content != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $decoded_file_content, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 3
                        )
                        || (
                            ($converted_file_content = $content->getConvertedContent())
                            && $converted_file_content != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $converted_file_content, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 4
                        )
                        || (
                            ($decoded_converted = $content->getConvertedDecodedContent())
                            && $decoded_converted != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $decoded_converted, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 5
                        )
                        || (
                            ($unescaped = $content->getUnescaped())
                            && $unescaped != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $unescaped, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 6
                        )
                        || (
                            preg_match('~' . $rec['sig_match'] . '~smi', $content_orig->getContent(), $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 2
                        )
                        || (
                            ($content_orig->getContent() !== $content->getContent())
                            && ($decoded_file_content = $content_orig->getNormDecodedFileContent())
                            && $decoded_file_content != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $decoded_file_content, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 3
                        )
                        || (
                            ($content_orig->getContent() !== $content->getContent())
                            && ($converted_file_content = $content_orig->getConvertedContent())
                            && $converted_file_content != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $converted_file_content, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 4
                        )
                        || (
                            ($content_orig->getContent() !== $content->getContent())
                            && ($decoded_converted = $content_orig->getConvertedDecodedContent())
                            && $decoded_converted != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $decoded_converted, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 5
                        )
                        || (
                            ($content_orig->getContent() !== $content->getContent())
                            && ($unescaped = $content_orig->getUnescaped())
                            && $unescaped != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $unescaped, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 6
                        )
                    ) {
                        $file_content = self::replaceString($file_content, '', $m[0][1], false, $serialized);
                        if ($serialized) {
                            $result[] = ['sig_type' => $rec['sig_type'], 'id' => $rec['id'], 'empty' => false];
                        } else {
                            $result[] = ['sig_type' => $rec['sig_type'], 'id' => $rec['id'], 'empty' => true];
                            $file_content = '';
                            $terminate = true;
                        }
                        $matched_not_cleaned = false;
                    }

                    break;
                case 3: // match signature against normalized file and delete it
                    $condition_num = 0; // for debug
                    if (
                        (
                            preg_match('~' . $rec['sig_match'] . '~smi', $content->getNormalized(), $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 1
                        )
                        || (
                            ($normalized_decoded = $content->getStripDecodedContent())
                            && $normalized_decoded != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $normalized_decoded, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 2
                        )
                        || (
                            ($decoded_converted = $content->getConvertedDecodedContent())
                            && $decoded_converted != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $decoded_converted, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 3
                        )
                        || (
                            preg_match('~' . $rec['sig_match'] . '~smi', $content_orig->getNormalized(), $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 1
                        )
                        || (
                            ($unescaped_norm = $content->getUnescapedNormalized())
                            && $unescaped_norm != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $unescaped_norm, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 5
                        )
                        || (
                            ($content_orig->getContent() !== $content->getContent())
                            && ($normalized_decoded = $content_orig->getStripDecodedContent())
                            && $normalized_decoded != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $normalized_decoded, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 2
                        )
                        || (
                            ($content_orig->getContent() !== $content->getContent())
                            && ($decoded_converted = $content_orig->getConvertedDecodedContent())
                            && $decoded_converted != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $decoded_converted, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 3
                        )
                        || (
                            ($content_orig->getContent() !== $content->getContent())
                            && ($unescaped_norm = $content_orig->getUnescapedNormalized())
                            && $unescaped_norm != ''
                            && preg_match('~' . $rec['sig_match'] . '~smi', $unescaped_norm, $m, PREG_OFFSET_CAPTURE)
                            && $condition_num = 5
                        )
                    ) {
                        $file_content = self::replaceString($file_content, '', $m[0][1], false, $serialized);
                        if ($serialized) {
                            $result[] = ['sig_type' => $rec['sig_type'], 'id' => $rec['id'], 'empty' => false];
                        } else {
                            $result[] = ['sig_type' => $rec['sig_type'], 'id' => $rec['id'], 'empty' => true];
                            $file_content = '';
                            $terminate = true;
                        }
                        $matched_not_cleaned = false;
                    }
                    break;
            }
        }
        self::removeBlackUrls($file_content, $clean_db, $result, $deobfuscate, $unescape);
        return $result;
    }

    public static function isEmpty($result)
    {
        foreach ($result as $item) {
            if($item['empty'] === true) {
                return true;
            }
        }
        return false;
    }

    public static function getSAItem($result)
    {
        foreach ($result as $item) {
            if($item['empty'] === true && ($item['sig_type'] == 1 || $item['sig_type'] == 3)) {
                return [$item];
            }
        }
        return $result;
    }

    private static function getReplaceFromRegExp($replace, $matches)
    {
        if (!empty($replace)) {
            if (preg_match('~\$(\d+)~smi', $replace)) {
                $replace = preg_replace_callback('~\$(\d+)~smi', function ($m) use ($matches) {
                    return isset($matches[(int)$m[1]]) ? $matches[(int)$m[1]][0] : '';
                }, $replace);
            }
        }
        return $replace;
    }

    private static function checkFalsePositives($l_Filename, $l_Unwrapped, $l_DeobfType, $deMapper)
    {
        if ($l_DeobfType == '') {
            return false;
        }
        switch ($l_DeobfType) {
            case 'Bitrix':
                foreach ($deMapper as $fkey => $fvalue) {
                    if ((strpos($l_Filename, $fkey) !== false) && (strpos($l_Unwrapped, $fvalue) !== false)) {
                        return true;
                    }
                }
                break;
        }
        return false;
    }

    private static function replaceString($file_content, $replace, $pos, $delta_len, &$serialized = false, $escapes = false)
    {
        $size2fix = self::getSerializedLength($file_content, $pos, $size2fix_pos);
        if ($size2fix) {
            $serialized = true;
            $delta_len = $delta_len ?: $size2fix;
            $quotes = $escapes ? substr_count($file_content, '\\', $pos, $delta_len) : 0;
            $file_content = substr_replace($file_content, $replace, $pos, $delta_len);
            $new_length = $size2fix - ($delta_len - strlen($replace)) + $quotes;
            $file_content = substr_replace($file_content, (string)$new_length, $size2fix_pos[0], $size2fix_pos[1]);
        } else {
            $file_content = substr_replace($file_content, $replace, $pos, $delta_len);
        }
        return $file_content;
    }

    private static function getSerializedLength($content, $offset, &$pos)
    {
        $ser_size = false;
        if (preg_match_all('~s:(\d+):\\\\?"~m', substr($content, 0, (int)$offset + 1), $m, PREG_OFFSET_CAPTURE | PREG_SET_ORDER)) {
            foreach ($m as $ser_chunk) {
                $start_chunk = $ser_chunk[0][1] + strlen($ser_chunk[0][0]);
                $end_chunk = $start_chunk + (int)$ser_chunk[1][0];
                if ($start_chunk <= $offset && $end_chunk > $offset) {
                    $ser_size = (int)$ser_chunk[1][0];
                    $pos[0] = $ser_chunk[1][1];
                    $pos[1] = strlen($ser_chunk[1][0]);
                    break;
                }
            }
        }
        return $ser_size;
    }

    private static function removeBlackUrls(&$file_content, $clean_db, &$result, $deobfuscate, $unescape)
    {
        if ($clean_db->getScanDB() === null || !class_exists('ScanCheckers')) {
            return;
        }
        $offset = 0;

        while (self::findBlackUrl($file_content, $fnd, $offset, $clean_db, $id)) {
            $offset += $fnd[0][1] + 1;
            $file_content = self::replaceString($file_content, '', $fnd[0][1], strlen($fnd[0][0]));
            $result[] = ['sig_type' => 2, 'id' => $clean_db->getScanDB()->blackUrls->getSig($id), 'empty' => false];
        }

        unset($content);
        $content = new ContentObject($file_content, $deobfuscate, $unescape);
        $offset = 0;
        while (self::findBlackUrl($content->getNormalized(), $fnd, $offset, $clean_db, $id)) {
            $offset += $fnd[0][1] + strlen($fnd[0][0]);
            $pos = Normalization::string_pos($file_content, $fnd[0][0]);
            if ($pos !== false) {
                $replace = self::getReplaceFromRegExp('', $content->getNormalized());
                $file_content = self::replaceString($file_content, $replace, $pos[0], $pos[1] - $pos[0] + 1);
                $result[] = ['sig_type' => 2, 'id' => $clean_db->getScanDB()->blackUrls->getSig($id), 'empty' => false];
            }
        }

        $offset = 0;
        unset($content);
        $content = new ContentObject($file_content, $deobfuscate, $unescape);
        while (self::findBlackUrl($content->getDecodedFragmentsString(), $fnd, $offset, $clean_db, $id)) {
            $offset += $fnd[0][1] + 1;
            $decoded_fragments = $content->getDecodedFragments();
            if (!empty($decoded_fragments)) {
                foreach ($decoded_fragments as $obfuscated => $deobfuscated) {
                    if (self::findBlackUrl($deobfuscated, $fnd_tmp, 0, $clean_db, $id)) {
                        $pos_obf = strpos($file_content, $obfuscated);
                        $len = strlen($obfuscated);
                        $file_content = self::replaceString($file_content, '', $pos_obf, $len);
                        $result[] = ['sig_type' => 2, 'id' => $clean_db->getScanDB()->blackUrls->getSig($id), 'empty' => false];
                    }
                }
            }
            unset($content);
            $content = new ContentObject($file_content, $deobfuscate, $unescape);
        }

        $offset = 0;
        unset($content);
        $content = new ContentObject($file_content, $deobfuscate, $unescape);
        while (self::findBlackUrl($content->getNormDecodedFragmentsString(), $fnd, $offset, $clean_db, $id)) {
            $offset += $fnd[0][1] + 1;
            $norm_decoded_fragments = $content->getNormDecodedFragments();
            if (!empty($norm_decoded_fragments)) {
                foreach ($norm_decoded_fragments as $obfuscated => $deobfuscated) {
                    if (self::findBlackUrl(Normalization::normalize($deobfuscated), $fnd_tmp, 0, $clean_db, $id)) {
                        $pos = Normalization::string_pos($file_content, $obfuscated);
                        if ($pos !== false) {
                            $file_content = self::replaceString($file_content, '', $pos[0], $pos[1] - $pos[0] + 1);
                            $result[] = ['sig_type' => 2, 'id' => $clean_db->getScanDB()->blackUrls->getSig($id), 'empty' => false];
                        }
                    }
                }
            }
            unset($content);
            $content = new ContentObject($file_content, $deobfuscate, $unescape);
            $offset = 0;
            while (self::findBlackUrl($content->getUnescaped(), $fnd, $offset, $clean_db, $id)) {
                $offset += $fnd[0][1] + strlen($fnd[0][0]);
                $pos = Normalization::string_pos($file_content, $fnd[0][0]);
                if ($pos !== false) {
                    $replace = self::getReplaceFromRegExp('', $content->getUnescaped());
                    $file_content = self::replaceString($file_content, $replace, $pos[0], $pos[1] - $pos[0] + 1);
                    $result[] = ['sig_type' => 2, 'id' => $clean_db->getScanDB()->blackUrls->getSig($id), 'empty' => false];
                }
            }

            unset($content);
            $content = new ContentObject($file_content, $deobfuscate, $unescape);
            $offset = 0;
            while (self::findBlackUrl($content->getUnescapedNormalized(), $fnd, $offset, $clean_db, $id)) {
                $offset += $fnd[0][1] + strlen($fnd[0][0]);
                $pos = Normalization::string_pos($file_content, $fnd[0][0]);
                if ($pos !== false) {
                    $replace = self::getReplaceFromRegExp('', $content->getUnescapedNormalized());
                    $file_content = self::replaceString($file_content, $replace, $pos[0], $pos[1] - $pos[0] + 1);
                    $result[] = ['sig_type' => 2, 'id' => $clean_db->getScanDB()->blackUrls->getSig($id), 'empty' => false];
                }
            }
            unset($content);
            $content = new ContentObject($file_content, $deobfuscate, $unescape);
        }
    }

    private static function findBlackUrl($item, &$fnd, $offset, $clean_db, &$id)
    {
        while (preg_match(self::URL_GRAB, $item, $fnd, PREG_OFFSET_CAPTURE, $offset)) {
            if (!ScanCheckers::isOwnUrl($fnd[2][0], $clean_db->getScanDB()->getOwnUrl())
                && (isset($clean_db->getScanDB()->whiteUrls) && !ScanCheckers::isUrlInList($fnd[2][0],
                        $clean_db->getScanDB()->whiteUrls->getDb()))
                && ($id = ScanCheckers::isUrlInList($fnd[2][0], $clean_db->getScanDB()->blackUrls->getDb()))
            ) {
                return true;
            }
            $offset = $fnd[0][1] + strlen($fnd[0][0]);
        }
        return false;
    }
}

class SignatureConverter {
    
    private $signatures         = [];
    private $cuted_signatures   = [];
    private $count_convert      = 0;
    
    public function __construct($clean_db) 
    {
        $this->signatures = $clean_db;
    }
    
    public function getCutSignature($sig_index) 
    {
        if (!isset($this->signatures[$sig_index])) {
            return false;
        }
        $signature = $this->signatures[$sig_index]['sig_match'];
        if (!isset($this->cuted_signatures[$sig_index])) {
            $cuted_signature = $this->cut($signature);
            if ($signature != $cuted_signature) {
                $this->cuted_signatures[$sig_index] = $cuted_signature;
            }
            else {
                $this->cuted_signatures[$sig_index] = false;
            }
            return $cuted_signature;
        }
        elseif ($this->cuted_signatures[$sig_index] === false) {
            return $signature;
        }
        return $this->cuted_signatures[$sig_index];
    }
    
    public function getCountConverted()
    {
        return $this->count_convert;
    }

    // /////////////////////////////////////////////////////////////////////////
    
    private function cut($signature)
    {
        $this->count_convert++;
        $regexp = '^'
        . '(?:\\\A)?'
        . '(?:\\\s\*)?'
        . '<\\\\\?'
        . '(?:\\\s\*)?'
        . '(?:\\\s\+)?'            
        . '(?:'
            .'php'
            . '|\(\?:php\)\?'
            . '|='
            . '|\(\?:php\|=\)\??'
            . '|\(\?:=\|php\)\??'
        . ')?'
        . '(?:\\\s\+)?'
    
        . '(.*?)'

        . '(?:\(\??:?\|?)?'
        . '\\\\\?>'
        . '(?:\\\s\*)?'
        . '(?:\|?\\\Z\)?)?'
        . '$';
    
        return preg_replace('~' . $regexp . '~smi', '\1', $signature);
    }
}

class Logger
{
    /**
     * $log_file - path and log file name
     * @var string
     */
    protected $log_file;
    /**
     * $file - file
     * @var string
     */
    protected $file;
    /**
     * dateFormat
     * @var string
     */
    protected $dateFormat = 'd-M-Y H:i:s';

    /**
     * @var array
     */
    const LEVELS  = ['ERROR' => 1, 'DEBUG' => 2,  'INFO' => 4, 'ALL' => 7];

    /**
     * @var int
     */
    private $level;

    /**
     * Class constructor
     *
     * @param string       $log_file - path and filename of log
     * @param string|array $level    - Level of logging
     *
     * @throws Exception
     */
    public function __construct($log_file = null, $level = 'INFO')
    {
        if (!$log_file) {
            return;
        }
        if (is_array($level)) {
            foreach ($level as $v) {
                if (!isset(self::LEVELS[$v])) {
                    $v = 'INFO';
                }
                $this->level |= self::LEVELS[$v];
            }
        } else {
            if (isset(self::LEVELS[$level])) {
                $this->level = self::LEVELS[$level];
            } else {
                $this->level = self::LEVELS['INFO'];
            }
        }

        $this->log_file = $log_file;
        //Create log file if it doesn't exist.
        if (!file_exists($log_file)) {
            fopen($log_file, 'w') or exit("Can't create $log_file!");
        }
        //Check permissions of file.
        if (!is_writable($log_file)) {
            //throw exception if not writable
            throw new Exception('ERROR: Unable to write to file!', 1);
        }
    }

    /**
     * Info method (write info message)
     * @param string $message
     * @return void
     */
    public function info($message)
    {
        if ($this->level & self::LEVELS['INFO']) {
            $this->writeLog($message, 'INFO');
        }

    }
    /**
     * Debug method (write debug message)
     * @param string $message
     * @return void
     */
    public function debug($message)
    {
        if ($this->level & self::LEVELS['DEBUG']) {
            $this->writeLog($message, 'DEBUG');
        }
    }
    /**
     * Error method (write error message)
     * @param string $message
     * @return void
     */
    public function error($message)
    {
        if ($this->level & self::LEVELS['ERROR']) {
            $this->writeLog($message, 'ERROR');
        }
    }

    /**
     * Write to log file
     * @param string $message
     * @param string $level
     * @return void
     */
    public function writeLog($message, $level)
    {
        if (!$this->log_file) {
            return;
        }
        // open log file
        if (!is_resource($this->file)) {
            $this->openLog();
        }
        //Grab time - based on timezone in php.ini
        $time = date($this->dateFormat);
        // Write time & message to end of file
        fwrite($this->file, "[$time] : [$level] - $message" . PHP_EOL);
    }
    /**
     * Open log file
     * @return void
     */
    private function openLog()
    {
        $openFile = $this->log_file;
        // 'a' option = place pointer at end of file
        $this->file = fopen($openFile, 'a') or exit("Can't open $openFile!");
    }
    /**
     * Class destructor
     */
    public function __destruct()
    {
        if ($this->file) {
            fclose($this->file);
        }
    }
}