<?php

namespace Delight\Auth;

use Delight\Base64\Base64;
use Delight\Cookie\Cookie;
use Delight\Cookie\Session;
use Delight\Db\PdoDatabase;
use Delight\Db\PdoDsn;
use Delight\Db\Throwable\Error;
use Delight\Db\Throwable\IntegrityConstraintViolationException;

/** Компонент, который предоставляет все функции и утилиты для безопасной аутентификации отдельных пользователей. */
final class Auth extends UserManager {

	const COOKIE_PREFIXES = [ Cookie::PREFIX_SECURE, Cookie::PREFIX_HOST ];
	const COOKIE_CONTENT_SEPARATOR = '~';

	/** @var string текущий IP-адрес пользователя */
	private $ipAddress;
	/** @var bool должн ли $throttling быть включенным (например, в работе) или отключенным (например, во время разработки) */
	private $throttling;
	/** @var int интервал в секундах, по истечении которого необходимо повторно синхронизировать данные сеанса с его официальным источником в базе данных */
	private $sessionResyncInterval;
	/** @var string имя файла cookie, используемого для функции "запомнить меня" */
	private $rememberCookieName;

	/**
	 * @param PdoDatabase|PdoDsn|\PDO $databaseConnection соединение с базой данных для работы
	 * @param string|null $ipAddress (необязательно) IP-адрес, который следует использовать вместо настройки по умолчанию (если есть), например когда есть прокси
	 * @param string|null $dbTablePrefix (необязательно) префикс для имен всех таблиц базы данных, используемых этим компонентом
	 * @param bool|null $throttling (необязательно) должно ли регулирование быть включено (например, в работе) или отключено (например, во время разработки)
	 * @param int|null $sessionResyncInterval (необязательно) интервал в секундах, по истечении которого необходимо повторно синхронизировать данные сеанса с его источником в базе данных.
	 * @param string|null $dbSchema (необязательно) имя схемы для всех таблиц базы данных, используемых этим компонентом
	 */
	public function __construct($databaseConnection, $ipAddress = null, $dbTablePrefix = null, $throttling = null, $sessionResyncInterval = null, $dbSchema = null) {
		parent::__construct($databaseConnection, $dbTablePrefix, $dbSchema);

		$this->ipAddress = !empty($ipAddress) ? $ipAddress : (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : null);
		$this->throttling = isset($throttling) ? (bool) $throttling : true;
		$this->sessionResyncInterval = isset($sessionResyncInterval) ? ((int) $sessionResyncInterval) : (60 * 5);
		$this->rememberCookieName = self::createRememberCookieName();

		$this->initSessionIfNecessary();
		$this->enhanceHttpSecurity();

		$this->processRememberDirective();
		$this->resyncSessionIfNecessary();
	}

	/** Инициализирует сеанс и устанавливает правильную конфигурацию */
	private function initSessionIfNecessary() {
		if (\session_status() === \PHP_SESSION_NONE) {
			// использовать файлы cookie для хранения идентификаторов сеансов
			\ini_set('session.use_cookies', 1);
			// использовать только файлы cookie (не отправлять идентификаторы сеанса в URL-адресах)
			\ini_set('session.use_only_cookies', 1);
			// не отправлять идентификаторы сеанса в URL-адресах
			\ini_set('session.use_trans_sid', 0);

			// запустить сеанс (запрашивает запись cookie на клиенте)
			@Session::start();
		}
	}

	/** Повышает безопасность приложения по протоколу HTTP (S), задавая определенные заголовки. */
	private function enhanceHttpSecurity() {
		// удалить раскрытие версии PHP (по крайней мере, где это возможно)
		\header_remove('X-Powered-By');

		// если пользователь вошел в систему
		if ($this->isLoggedIn()) {
			// предотвратить кликджекинг
			\header('X-Frame-Options: sameorigin');
			// предотвращение прослушивания контента (сниффинг MIME)
			\header('X-Content-Type-Options: nosniff');

			// отключить кеширование потенциально конфиденциальных данных
			\header('Cache-Control: no-store, no-cache, must-revalidate', true);
			\header('Expires: Thu, 19 Nov 1981 00:00:00 GMT', true);
			\header('Pragma: no-cache', true);
		}
	}

	/** Проверяет наличие установленной директивы «запомнить меня» и обрабатывает автоматический вход (при необходимости) */
	private function processRememberDirective() {
		// если пользователь еще не вошел в систему
		if (!$this->isLoggedIn()) {
			// если в настоящее время нет файла cookie для функции «запомнить меня»
			if (!isset($_COOKIE[$this->rememberCookieName])) {
				// если был обнаружен старый файл cookie
				if (isset($_COOKIE['auth_remember'])) {
					// вместо этого используем значение из этого старого файла cookie
					$_COOKIE[$this->rememberCookieName] = $_COOKIE['auth_remember'];
				}
			}

			// если запоминающийся cookie установлен
			if (isset($_COOKIE[$this->rememberCookieName])) {
				// предполагать, что файл cookie и его содержимое недействительны, пока не будет доказано обратное
				$valid = false;

				// разделить содержимое файла cookie на селектор и токен
				$parts = \explode(self::COOKIE_CONTENT_SEPARATOR, $_COOKIE[$this->rememberCookieName], 2);

				// если были найдены и селектор, и токен
				if (!empty($parts[0]) && !empty($parts[1])) {
					try {
						$rememberData = $this->db->selectRow(
							'SELECT a.user, a.token, a.expires, b.email, b.username, b.status, b.roles_mask, b.force_logout FROM ' . $this->makeTableName('users_remembered') . ' AS a JOIN ' . $this->makeTableName('users') . ' AS b ON a.user = b.id WHERE a.selector = ?',
							[ $parts[0] ]
						);
					}
					catch (Error $e) {
						throw new DatabaseError($e->getMessage());
					}

					if (!empty($rememberData)) {
						if ($rememberData['expires'] >= \time()) {
							if (\password_verify($parts[1], $rememberData['token'])) {
								// cookie и его содержимое прошли проверку
								$valid = true;

								$this->onLoginSuccessful($rememberData['user'], $rememberData['email'], $rememberData['username'], $rememberData['status'], $rememberData['roles_mask'], $rememberData['force_logout'], true);
							}
						}
					}
				}

				// если cookie или его содержимое недействительны
				if (!$valid) {
					// пометить файл cookie как поврежденный, чтобы предотвратить дальнейшие попытки чтения его
					$this->setRememberCookie('', '', \time() + 60 * 60 * 24 * 365.25);
				}
			}
		}
	}

	private function resyncSessionIfNecessary() {
		// если пользователь вошел в систему
		if ($this->isLoggedIn()) {
			if (!isset($_SESSION[self::SESSION_FIELD_LAST_RESYNC])) {
				$_SESSION[self::SESSION_FIELD_LAST_RESYNC] = 0;
			}

			// если пришло время для повторной синхронизации
			if (($_SESSION[self::SESSION_FIELD_LAST_RESYNC] + $this->sessionResyncInterval) <= \time()) {
				// снова получить достоверные данные из базы данных
				try {
					$authoritativeData = $this->db->selectRow(
						'SELECT email, username, status, roles_mask, force_logout FROM ' . $this->makeTableName('users') . ' WHERE id = ?',
						[ $this->getUserId() ]
					);
				}
				catch (Error $e) {
					throw new DatabaseError($e->getMessage());
				}

				// если данные пользователя были найдены
				if (!empty($authoritativeData)) {
					if (!isset($_SESSION[self::SESSION_FIELD_FORCE_LOGOUT])) {
						$_SESSION[self::SESSION_FIELD_FORCE_LOGOUT] = 0;
					}

					// если счетчик, отслеживающий принудительные выходы из системы, был увеличен
					if ($authoritativeData['force_logout'] > $_SESSION[self::SESSION_FIELD_FORCE_LOGOUT]) {
						// пользователь должен выйти из системы
						$this->logOut();
					}
					// если счетчик, отслеживающий принудительные выходы из системы, остался неизменным
					else {
						// данные сеанса необходимо обновить
						$_SESSION[self::SESSION_FIELD_EMAIL] = $authoritativeData['email'];
						$_SESSION[self::SESSION_FIELD_USERNAME] = $authoritativeData['username'];
						$_SESSION[self::SESSION_FIELD_STATUS] = (int) $authoritativeData['status'];
						$_SESSION[self::SESSION_FIELD_ROLES] = (int) $authoritativeData['roles_mask'];

						// выполнение повторной синхронизации
						$_SESSION[self::SESSION_FIELD_LAST_RESYNC] = \time();
					}
				}
				// если данные для пользователя не найдены
				else {
					// если учетная запись могла быть удалена, то выход из системы
					$this->logOut();
				}
			}
		}
	}

	/**
	 * Попытки зарегистрировать пользователя
	 *
	 * Если вы хотите, чтобы учетная запись пользователя была активирована по умолчанию, передайте null в качестве обратного вызова.
	 *
	 * Если вы хотите, чтобы пользователь сначала подтвердил свой адрес электронной почты, передайте анонимную функцию в качестве обратного вызова
	 *
	 * Функция обратного вызова должна иметь следующую подпись:
	 *
	 * `function ($selector, $token)`
	 *
	 * Обе части информации должны быть отправлены пользователю, как правило, встроены в ссылку.
	 *
	 * Когда пользователь хочет подтвердить свой адрес электронной почты в качестве следующего шага, снова потребуются обе части.
	 *
	 * @param string $email адрес электронной почты для регистрации
	 * @param string $password пароль для новой учетной записи
	 * @param string|null $username (необязательно) имя пользователя, которое будет отображаться
	 * @param callable|null $callback (необязательно) функция, которая отправляет пользователю электронное письмо с подтверждением
	 * @return int ID созданного пользователя (если есть)
	 * @throws InvalidEmailException если адрес электронной почты недействителен
	 * @throws InvalidPasswordException если пароль был недействителен
	 * @throws UserAlreadyExistsException если пользователь с указанным адресом электронной почты уже существует
	 * @throws TooManyRequestsException если количество разрешенных попыток / запросов было превышено
	 * @throws AuthError если возникла внутренняя проблема
	 *
	 * @see confirmEmail
	 * @see confirmEmailAndSignIn
	 */
	public function register($email, $password, $username = null, callable $callback = null) {
		$this->throttle([ 'enumerateUsers', $this->getIpAddress() ], 1, (60 * 60), 75);
		$this->throttle([ 'createNewAccount', $this->getIpAddress() ], 1, (60 * 60 * 12), 5, true);

		$newUserId = $this->createUserInternal(false, $email, $password, $username, $callback);

		$this->throttle([ 'createNewAccount', $this->getIpAddress() ], 1, (60 * 60 * 12), 5, false);

		return $newUserId;
	}

	/**
     * Попытки зарегистрировать пользователя, гарантируя, что имя пользователя уникально
     *
     * Если вы хотите, чтобы учетная запись пользователя была активирована по умолчанию, передайте `null` в качестве обратного вызова
     *
     * Если вы хотите, чтобы пользователь сначала подтвердил свой адрес электронной почты, передайте анонимную функцию в качестве обратного вызова
     *
     * Функция обратного вызова должна иметь следующую подпись:
     *
	 * `function ($selector, $token)`
	 *
     * Обе части информации должны быть отправлены пользователю, как правило, встроены в ссылку.
     *
     * Когда пользователь хочет подтвердить свой адрес электронной почты в качестве следующего шага, снова потребуются обе части.
     *
	 * @param string $email адрес электронной почты для регистрации
	 * @param string $password пароль для новой учетной записи
	 * @param string|null $username (необязательно) имя пользователя, которое будет отображаться
	 * @param callable|null $callback (необязательно) функция, которая отправляет пользователю электронное письмо с подтверждением
	 * @return int ID созданного пользователя (если есть)
	 * @throws InvalidEmailException если адрес электронной почты недействителен
	 * @throws InvalidPasswordException если пароль был недействителен
	 * @throws UserAlreadyExistsException если пользователь с указанным адресом электронной почты уже существует
	 * @throws DuplicateUsernameException если указанное имя пользователя не было уникальным
	 * @throws TooManyRequestsException если количество разрешенных попыток / запросов было превышено
	 * @throws AuthError если возникла внутренняя проблема
	 *
	 * @see confirmEmail
	 * @see confirmEmailAndSignIn
	 */
	public function registerWithUniqueUsername($email, $password, $username = null, callable $callback = null) {
		$this->throttle([ 'enumerateUsers', $this->getIpAddress() ], 1, (60 * 60), 75);
		$this->throttle([ 'createNewAccount', $this->getIpAddress() ], 1, (60 * 60 * 12), 5, true);

		$newUserId = $this->createUserInternal(true, $email, $password, $username, $callback);

		$this->throttle([ 'createNewAccount', $this->getIpAddress() ], 1, (60 * 60 * 12), 5, false);

		return $newUserId;
	}

	/**
	 * Попытки войти в систему пользователя с его адресом электронной почты и паролем
	 *
	 * @param string $email адрес электронной почты пользователя
	 * @param string $password пароль пользователя
	 * @param int|null $rememberDuration (необязательно) время в секундах, в течение которого пользователь остается в системе («запомнить меня»)
	 * @param callable|null $onBeforeSuccess (необязательно) функция, которая получает идентификатор пользователя в качестве единственного параметра и выполняется до успешной аутентификации; должен вернуть true для продолжения или false для отмены
	 * @throws InvalidEmailException если адрес электронной почты недействителен или не может быть найден
	 * @throws InvalidPasswordException если пароль был недействителен
	 * @throws EmailNotVerifiedException если адрес электронной почты еще не был подтвержден по электронной почте с подтверждением
	 * @throws AttemptCancelledException если попытка была отменена предоставленным обратным вызовом, который выполняется до успеха
	 * @throws TooManyRequestsException если количество разрешенных попыток / запросов было превышено
	 * @throws AuthError если возникла внутренняя проблема
	 */
	public function login($email, $password, $rememberDuration = null, callable $onBeforeSuccess = null) {
		$this->throttle([ 'attemptToLogin', 'email', $email ], 500, (60 * 60 * 24), null, true);

		$this->authenticateUserInternal($password, $email, null, $rememberDuration, $onBeforeSuccess);
	}

	/**
	 * Попытки войти в систему пользователя с его именем пользователя и паролем
	 *
	 * При использовании этого метода для аутентификации пользователей следует убедиться, что имена пользователей уникальны.
	 *
	 * @param string $username имя пользователя
	 * @param string $password пароль пользователя
	 * @param int|null $rememberDuration (необязательно) время в секундах, в течение которого пользователь остается в системе («запомни меня»)
	 * @param callable|null $onBeforeSuccess (необязательно) функция, которая получает идентификатор пользователя в качестве единственного параметра и выполняется до успешной аутентификации; должен вернуть true для продолжения или false для отмены
	 * @throws UnknownUsernameException если указанное имя пользователя не существует
	 * @throws AmbiguousUsernameException если указанное имя пользователя неоднозначно, т.е. есть несколько пользователей с таким именем
	 * @throws InvalidPasswordException если пароль был недействителен
	 * @throws EmailNotVerifiedException если адрес электронной почты еще не был подтвержден по электронной почте с подтверждением
	 * @throws AttemptCancelledException если попытка была отменена предоставленным обратным вызовом, который выполняется до успеха
	 * @throws TooManyRequestsException если количество разрешенных попыток / запросов было превышено
	 * @throws AuthError если возникла внутренняя проблема
	 */
	public function loginWithUsername($username, $password, $rememberDuration = null, callable $onBeforeSuccess = null) {
		$this->throttle([ 'attemptToLogin', 'username', $username ], 500, (60 * 60 * 24), null, true);

		$this->authenticateUserInternal($password, null, $username, $rememberDuration, $onBeforeSuccess);
	}

	/**
     * Попытки снова подтвердить пароль вошедшего в систему пользователя
     *
     * Всякий раз, когда вы хотите снова подтвердить личность пользователя, например до
     * пользователю разрешено совершать какие-то «опасные» действия, вы должны
     * используйте этот метод, чтобы подтвердить, что пользователь является тем, кем он себя называет.
     *
     * Например, когда пользователя запомнили долгоживущим файлом cookie.
     * и, таким образом, {@see isRemembered} возвращает "true", это означает, что
     * пользователь уже довольно долгое время не вводит свой пароль.
	 *
	 * @param string $password пароль пользователя
	 * @return bool был ли введен правильный пароль
	 * @throws NotLoggedInException если пользователь в настоящее время не вошел в систему
	 * @throws TooManyRequestsException если количество разрешенных попыток / запросов было превышено
	 * @throws AuthError если возникла внутренняя проблема
	 */
	public function reconfirmPassword($password) {
		if ($this->isLoggedIn()) {
			try {
				$password = self::validatePassword($password);
			}
			catch (InvalidPasswordException $e) {
				return false;
			}

			$this->throttle([ 'reconfirmPassword', $this->getIpAddress() ], 3, (60 * 60), 4, true);

			try {
				$expectedHash = $this->db->selectValue(
					'SELECT password FROM ' . $this->makeTableName('users') . ' WHERE id = ?',
					[ $this->getUserId() ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}

			if (!empty($expectedHash)) {
				$validated = \password_verify($password, $expectedHash);

				if (!$validated) {
					$this->throttle([ 'reconfirmPassword', $this->getIpAddress() ], 3, (60 * 60), 4, false);
				}

				return $validated;
			}
			else {
				throw new NotLoggedInException();
			}
		}
		else {
			throw new NotLoggedInException();
		}
	}

	/**
	 * Логи выхода пользователя из систмы
	 *
	 * @throws AuthError если возникла внутренняя проблема
	 */
	public function logOut() {
		// если пользователь вошел в систему
		if ($this->isLoggedIn()) {
			// получить любую локально существующую директиву
			$rememberDirectiveSelector = $this->getRememberDirectiveSelector();

			// если такая директива запоминания существует
			if (isset($rememberDirectiveSelector)) {
				// удалить директиву локального запоминания
				$this->deleteRememberDirectiveForUserById(
					$this->getUserId(),
					$rememberDirectiveSelector
				);
			}

			// удалить все переменные сеанса, поддерживаемые этой библиотекой
			unset($_SESSION[self::SESSION_FIELD_LOGGED_IN]);
			unset($_SESSION[self::SESSION_FIELD_USER_ID]);
			unset($_SESSION[self::SESSION_FIELD_EMAIL]);
			unset($_SESSION[self::SESSION_FIELD_USERNAME]);
			unset($_SESSION[self::SESSION_FIELD_STATUS]);
			unset($_SESSION[self::SESSION_FIELD_ROLES]);
			unset($_SESSION[self::SESSION_FIELD_REMEMBERED]);
			unset($_SESSION[self::SESSION_FIELD_LAST_RESYNC]);
			unset($_SESSION[self::SESSION_FIELD_FORCE_LOGOUT]);
		}
	}

	/**
	 * Выполняет выход пользователя из всех остальных сеансов (кроме текущего)
	 *
	 * @throws NotLoggedInException если пользователь в настоящее время не вошел в систему
	 * @throws AuthError если возникла внутренняя проблема
	 */
	public function logOutEverywhereElse() {
		if (!$this->isLoggedIn()) {
			throw new NotLoggedInException();
		}

		// определить дату истечения срока действия любой локально существующей директивы
		$previousRememberDirectiveExpiry = $this->getRememberDirectiveExpiry();

		// запланировать принудительный выход из системы во всех сеансах
		$this->forceLogoutForUserById($this->getUserId());

       // следующее поле сеанса могло не быть инициализировано для сеансов, которые уже существовали до введения этой функции
		if (!isset($_SESSION[self::SESSION_FIELD_FORCE_LOGOUT])) {
			$_SESSION[self::SESSION_FIELD_FORCE_LOGOUT] = 0;
		}

		// убедитесь, что мы просто пропустим или проигнорируем следующий принудительный выход из системы (который мы только что вызвали) в текущем сеансе
		$_SESSION[self::SESSION_FIELD_FORCE_LOGOUT]++;

		// повторно сгенерировать идентификатор сеанса, чтобы предотвратить атаки фиксации сеанса (запрашивает запись cookie на клиенте)
		Session::regenerate(true);

		// если ранее существовала директива запоминания
		if (isset($previousRememberDirectiveExpiry)) {
			// восстановить директиву со старой датой истечения срока действия, но с новыми учетными данными
			$this->createRememberDirective(
				$this->getUserId(),
				$previousRememberDirectiveExpiry - \time()
			);
		}
	}

	/**
	 * Выходит из системы во всех сеансах
	 *
	 * @throws NotLoggedInException если пользователь в настоящее время не вошел в систему
	 * @throws AuthError если возникла внутренняя проблема
	 */
	public function logOutEverywhere() {
		if (!$this->isLoggedIn()) {
			throw new NotLoggedInException();
		}

		// запланировать принудительный выход из системы во всех сеансах
		$this->forceLogoutForUserById($this->getUserId());
		// и немедленно примените выход из системы локально
		$this->logOut();
	}

	/**
	 * Уничтожает все данные сеанса
	 *
	 * @throws AuthError если возникла внутренняя проблема
	 */
	public function destroySession() {
		// удалить все переменные сеанса без исключения
		$_SESSION = [];
		// удалить файл cookie сеанса
		$this->deleteSessionCookie();
		// пусть PHP уничтожит сеанс
		\session_destroy();
	}

	/**
	 * Создает новую директиву, удерживающую пользователя в системе («запомни меня»)
	 *
	 * @param int $userId ID пользователя, который будет оставаться в системе
	 * @param int $duration продолжительность в секундах
	 * @throws AuthError если возникла внутренняя проблема
	 */
	private function createRememberDirective($userId, $duration) {
		$selector = self::createRandomString(24);
		$token = self::createRandomString(32);
		$tokenHashed = \password_hash($token, \PASSWORD_DEFAULT);
		$expires = \time() + ((int) $duration);

		try {
			$this->db->insert(
				$this->makeTableNameComponents('users_remembered'),
				[
					'user' => $userId,
					'selector' => $selector,
					'token' => $tokenHashed,
					'expires' => $expires
				]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		$this->setRememberCookie($selector, $token, $expires);
	}

	protected function deleteRememberDirectiveForUserById($userId, $selector = null) {
		parent::deleteRememberDirectiveForUserById($userId, $selector);

		$this->setRememberCookie(null, null, \time() - 3600);
	}

	/**
	 * Устанавливает или обновляет файл cookie, который управляет токеном «запомнить меня».
	 *
	 * @param string|null $selector селектор из пары селектор/токен
	 * @param string|null $token токен из пары селектор/токен
	 * @param int $expires время UNIX в секундах, по истечении которого токен должен истечь
	 * @throws AuthError если возникла внутренняя проблема
	 */
	private function setRememberCookie($selector, $token, $expires) {
		$params = \session_get_cookie_params();

		if (isset($selector) && isset($token)) {
			$content = $selector . self::COOKIE_CONTENT_SEPARATOR . $token;
		}
		else {
			$content = '';
		}

		// сохранить файл cookie с помощью селектора и токена (запрашивает запись файла cookie на клиенте)
		$cookie = new Cookie($this->rememberCookieName);
		$cookie->setValue($content);
		$cookie->setExpiryTime($expires);
		$cookie->setPath($params['path']);
		$cookie->setDomain($params['domain']);
		$cookie->setHttpOnly($params['httponly']);
		$cookie->setSecureOnly($params['secure']);
		$result = $cookie->save();

		if ($result === false) {
			throw new HeadersAlreadySentError();
		}

		// если мы удаляли файл cookie выше
		if (!isset($selector) || !isset($token)) {
			$cookie = new Cookie('auth_remember');
			$cookie->setPath((!empty($params['path'])) ? $params['path'] : '/');
			$cookie->setDomain($params['domain']);
			$cookie->setHttpOnly($params['httponly']);
			$cookie->setSecureOnly($params['secure']);
			$cookie->delete();
		}
	}

	protected function onLoginSuccessful($userId, $email, $username, $status, $roles, $forceLogout, $remembered) {
		// обновить метку времени последнего входа пользователя
		try {
			$this->db->update(
				$this->makeTableNameComponents('users'),
				[ 'last_login' => \time() ],
				[ 'id' => $userId ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		parent::onLoginSuccessful($userId, $email, $username, $status, $roles, $forceLogout, $remembered);
	}

	/**
	 * Удаляет cookie сеанса на клиенте
	 *
	 * @throws AuthError если возникла внутренняя проблема
	 */
	private function deleteSessionCookie() {
		$params = \session_get_cookie_params();

		// запросить удаление файла cookie сеанса (запрашивает запись файла cookie на клиенте)
		$cookie = new Cookie(\session_name());
		$cookie->setPath($params['path']);
		$cookie->setDomain($params['domain']);
		$cookie->setHttpOnly($params['httponly']);
		$cookie->setSecureOnly($params['secure']);
		$result = $cookie->delete();

		if ($result === false) {
			throw new HeadersAlreadySentError();
		}
	}

	/**
     * Подтверждает адрес электронной почты (и активирует учетную запись), указав правильную пару селектор/токен
     *
     * Пара селектор/токен должна быть сгенерирована ранее при регистрации новой учетной записи.
	 *
	 * @param string $selector селектор из пары селектор/токен
	 * @param string $token токен из пары селектор/токен
	 * @return string[] массив со старым адресом электронной почты (если есть) в нулевом индексе и новым адресом электронной почты (который только что был проверен) в индексе один
	 * @throws InvalidSelectorTokenPairException если либо селектор, либо токен был неправильным
	 * @throws TokenExpiredException если срок действия токена уже истек
	 * @throws UserAlreadyExistsException если была сделана попытка изменить адрес электронной почты на (сейчас) занятый адрес
	 * @throws TooManyRequestsException если количество разрешенных попыток/запросов было превышено
	 * @throws AuthError если возникла внутренняя проблема
	 */
	public function confirmEmail($selector, $token) {
		$this->throttle([ 'confirmEmail', $this->getIpAddress() ], 5, (60 * 60), 10);
		$this->throttle([ 'confirmEmail', 'selector', $selector ], 3, (60 * 60), 10);
		$this->throttle([ 'confirmEmail', 'token', $token ], 3, (60 * 60), 10);

		try {
			$confirmationData = $this->db->selectRow(
				'SELECT a.id, a.user_id, a.email AS new_email, a.token, a.expires, b.email AS old_email FROM ' . $this->makeTableName('users_confirmations') . ' AS a JOIN ' . $this->makeTableName('users') . ' AS b ON b.id = a.user_id WHERE a.selector = ?',
				[ $selector ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		if (!empty($confirmationData)) {
			if (\password_verify($token, $confirmationData['token'])) {
				if ($confirmationData['expires'] >= \time()) {
					// аннулировать любые потенциальные невыполненные запросы на сброс пароля
					try {
						$this->db->delete(
							$this->makeTableNameComponents('users_resets'),
							[ 'user' => $confirmationData['user_id'] ]
						);
					}
					catch (Error $e) {
						throw new DatabaseError($e->getMessage());
					}

					// отметьте адрес электронной почты как подтвержденный (и, возможно, обновите его на новый указанный адрес)
					try {
						$this->db->update(
							$this->makeTableNameComponents('users'),
							[
								'email' => $confirmationData['new_email'],
								'verified' => 1
							],
							[ 'id' => $confirmationData['user_id'] ]
						);
					}
					catch (IntegrityConstraintViolationException $e) {
						throw new UserAlreadyExistsException();
					}
					catch (Error $e) {
						throw new DatabaseError($e->getMessage());
					}

					// если пользователь в настоящее время вошел в систему
					if ($this->isLoggedIn()) {
						// если пользователь только что подтвердил адрес электронной почты для своей учетной записи
						if ($this->getUserId() === $confirmationData['user_id']) {
							// немедленно обновить адрес электронной почты в текущем сеансе
							$_SESSION[self::SESSION_FIELD_EMAIL] = $confirmationData['new_email'];
						}
					}

					// использовать токен, который используется только для подтверждения
					try {
						$this->db->delete(
							$this->makeTableNameComponents('users_confirmations'),
							[ 'id' => $confirmationData['id'] ]
						);
					}
					catch (Error $e) {
						throw new DatabaseError($e->getMessage());
					}

					// если адрес электронной почты не был изменен, а просто подтвержден
					if ($confirmationData['old_email'] === $confirmationData['new_email']) {
						// вывод не должен содержать никаких предыдущих адресов электронной почты
						$confirmationData['old_email'] = null;
					}

					return [
						$confirmationData['old_email'],
						$confirmationData['new_email']
					];
				}
				else {
					throw new TokenExpiredException();
				}
			}
			else {
				throw new InvalidSelectorTokenPairException();
			}
		}
		else {
			throw new InvalidSelectorTokenPairException();
		}
	}

	/**
     * Подтверждает адрес электронной почты и активирует учетную запись, указав правильную пару селектор / токен
     *
     * Пара селектор/токен должна быть сгенерирована ранее при регистрации новой учетной записи.
     *
     * Пользователь будет автоматически авторизован, если эта операция прошла успешно.
	 *
	 * @param string $selector селектор из пары селектор/токен
	 * @param string $token токен из пары селектор/токен
	 * @param int|null $rememberDuration (необязательно) время в секундах, в течение которого пользователь остается в системе («запомни меня»)
	 * @return string[] массив со старым адресом электронной почты (если есть) в нулевом индексе и новым адресом электронной почты (который только что был проверен) в индексе один
	 * @throws InvalidSelectorTokenPairException если либо селектор, либо токен был неправильным
	 * @throws TokenExpiredException если срок действия токена уже истек
	 * @throws UserAlreadyExistsException если была сделана попытка изменить адрес электронной почты на (сейчас) занятый адрес
	 * @throws TooManyRequestsException если количество разрешенных попыток / запросов было превышено
	 * @throws AuthError если возникла внутренняя проблема
	 */
	public function confirmEmailAndSignIn($selector, $token, $rememberDuration = null) {
		$emailBeforeAndAfter = $this->confirmEmail($selector, $token);

		if (!$this->isLoggedIn()) {
			if ($emailBeforeAndAfter[1] !== null) {
				$emailBeforeAndAfter[1] = self::validateEmailAddress($emailBeforeAndAfter[1]);

				$userData = $this->getUserDataByEmailAddress(
					$emailBeforeAndAfter[1],
					[ 'id', 'email', 'username', 'status', 'roles_mask', 'force_logout' ]
				);

				$this->onLoginSuccessful($userData['id'], $userData['email'], $userData['username'], $userData['status'], $userData['roles_mask'], $userData['force_logout'], true);

				if ($rememberDuration !== null) {
					$this->createRememberDirective($userData['id'], $rememberDuration);
				}
			}
		}

		return $emailBeforeAndAfter;
	}

	/**
	 * Изменяет пароль текущего пользователя, вошедшего в систему, при этом для проверки требуется старый пароль.
	 *
	 * @param string $oldPassword старый пароль для подтверждения владения учетной записью
	 * @param string $newPassword новый пароль, который должен быть установлен
	 * @throws NotLoggedInException если пользователь в настоящее время не вошел в систему
	 * @throws InvalidPasswordException если либо старый пароль был неправильным, либо желаемый новый был недействителен
	 * @throws TooManyRequestsException если количество разрешенных попыток/запросов было превышено
	 * @throws AuthError если возникла внутренняя проблема
	 */
	public function changePassword($oldPassword, $newPassword) {
		if ($this->reconfirmPassword($oldPassword)) {
			$this->changePasswordWithoutOldPassword($newPassword);
		}
		else {
			throw new InvalidPasswordException();
		}
	}

	/**
	 * Изменяет текущий пароль пользователя, вошедшего в систему, не требуя старый пароль для проверки
	 *
	 * @param string $newPassword новый пароль, который должен быть установлен
	 * @throws NotLoggedInException если пользователь в настоящее время не вошел в систему
	 * @throws InvalidPasswordException если желаемый новый пароль недействителен
	 * @throws AuthError если возникла внутренняя проблема
	 */
	public function changePasswordWithoutOldPassword($newPassword) {
		if ($this->isLoggedIn()) {
			$newPassword = self::validatePassword($newPassword);
			$this->updatePasswordInternal($this->getUserId(), $newPassword);

			try {
				$this->logOutEverywhereElse();
			}
			catch (NotLoggedInException $ignored) {}
		}
		else {
			throw new NotLoggedInException();
		}
	}

	/**
     * Попытки изменить адрес электронной почты текущего пользователя, вошедшего в систему (что требует подтверждения)
     *
     * Функция обратного вызова должна иметь следующую подпись:
	 *
	 * `function ($selector, $token)`
     *
     * Обе части информации должны быть отправлены пользователю, как правило, встроены в ссылку.
     *
     * Когда пользователь хочет подтвердить свой адрес электронной почты в качестве следующего шага, снова потребуются обе части.
     *
	 * @param string $newEmail желаемый новый адрес электронной почты
	 * @param callable $callback функция, которая отправляет пользователю электронное письмо с подтверждением
	 * @throws InvalidEmailException если желаемый новый адрес электронной почты недействителен
	 * @throws UserAlreadyExistsException если пользователь с желаемым новым адресом электронной почты уже существует
	 * @throws EmailNotVerifiedException если текущий (старый) адрес электронной почты еще не подтвержден
	 * @throws NotLoggedInException если пользователь в настоящее время не вошел в систему
	 * @throws TooManyRequestsException если количество разрешенных попыток/запросов было превышено
	 * @throws AuthError если возникла внутренняя проблема
	 *
	 * @see confirmEmail
	 * @see confirmEmailAndSignIn
	 */
	public function changeEmail($newEmail, callable $callback) {
		if ($this->isLoggedIn()) {
			$newEmail = self::validateEmailAddress($newEmail);

			$this->throttle([ 'enumerateUsers', $this->getIpAddress() ], 1, (60 * 60), 75);

			try {
				$existingUsersWithNewEmail = $this->db->selectValue(
					'SELECT COUNT(*) FROM ' . $this->makeTableName('users') . ' WHERE email = ?',
					[ $newEmail ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}

			if ((int) $existingUsersWithNewEmail !== 0) {
				throw new UserAlreadyExistsException();
			}

			try {
				$verified = $this->db->selectValue(
					'SELECT verified FROM ' . $this->makeTableName('users') . ' WHERE id = ?',
					[ $this->getUserId() ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}

			// перед продолжением убедимся, что по крайней мере текущий (старый) адрес электронной почты был проверен.
			if ((int) $verified !== 1) {
				throw new EmailNotVerifiedException();
			}

			$this->throttle([ 'requestEmailChange', 'userId', $this->getUserId() ], 1, (60 * 60 * 24));
			$this->throttle([ 'requestEmailChange', $this->getIpAddress() ], 1, (60 * 60 * 24), 3);

			$this->createConfirmationRequest($this->getUserId(), $newEmail, $callback);
		}
		else {
			throw new NotLoggedInException();
		}
	}

	/**
     * Попытки повторно отправить более ранний запрос подтверждения для пользователя с указанным адресом электронной почты
     *
     * Функция обратного вызова должна иметь следующую подпись:
	 *
	 * `function ($selector, $token)`
     *
     * Обе части информации должны быть отправлены пользователю, как правило, встроены в ссылку.
     *
     * Когда пользователь хочет подтвердить свой адрес электронной почты в качестве следующего шага, снова потребуются обе части.
     *
	 * @param string $email адрес электронной почты пользователя для повторной отправки запроса подтверждения для
	 * @param callable $callback функция, отправляющая пользователю запрос на подтверждение
	 * @throws ConfirmationRequestNotFound если не было найдено ни одного предыдущего запроса, который можно было бы повторно отправить
	 * @throws TooManyRequestsException если количество разрешенных попыток/запросов было превышено
	 */
	public function resendConfirmationForEmail($email, callable $callback) {
		$this->throttle([ 'enumerateUsers', $this->getIpAddress() ], 1, (60 * 60), 75);

		$this->resendConfirmationForColumnValue('email', $email, $callback);
	}

	/**
     * Попытки повторно отправить более ранний запрос подтверждения для пользователя с указанным ID
     *
     * Функция обратного вызова должна иметь следующую подпись:
	 *
	 * `function ($selector, $token)`
	 *
     * Обе части информации должны быть отправлены пользователю, как правило, встроены в ссылку.
     *
     * Когда пользователь хочет подтвердить свой адрес электронной почты в качестве следующего шага, снова потребуются обе части.
	 *
	 * @param int $userId идентификатор пользователя для повторной отправки запроса подтверждения для
	 * @param callable $callback функция, отправляющая пользователю запрос на подтверждение
	 * @throws ConfirmationRequestNotFound если не было найдено ни одного предыдущего запроса, который можно было бы повторно отправить
	 * @throws TooManyRequestsException если количество разрешенных попыток/запросов было превышено
	 */
	public function resendConfirmationForUserId($userId, callable $callback) {
		$this->resendConfirmationForColumnValue('user_id', $userId, $callback);
	}

	/**
     * Попытки повторно отправить более ранний запрос подтверждения
     *
     * Функция обратного вызова должна иметь следующую подпись:
	 *
	 * `function ($selector, $token)`
	 *
     * Обе части информации должны быть отправлены пользователю, как правило, встроены в ссылку.
     *
     * Когда пользователь хочет подтвердить свой адрес электронной почты в качестве следующего шага, снова потребуются обе части.
     *
     * Никогда не передавать ненадежный ввод в параметр, который принимает имя столбца.
	 *
	 * @param string $columnName имя столбца для фильтрации по
	 * @param mixed $columnValue значение, которое нужно искать в выбранном столбце
	 * @param callable $callback функция, отправляющая пользователю запрос на подтверждение
	 * @throws ConfirmationRequestNotFound если не было найдено ни одного предыдущего запроса, который можно было бы повторно отправить
	 * @throws TooManyRequestsException если количество разрешенных попыток/запросов было превышено
	 * @throws AuthError если возникла внутренняя проблема
	 */
	private function resendConfirmationForColumnValue($columnName, $columnValue, callable $callback) {
		try {
			$latestAttempt = $this->db->selectRow(
				'SELECT user_id, email FROM ' . $this->makeTableName('users_confirmations') . ' WHERE ' . $columnName . ' = ? ORDER BY id DESC LIMIT 1 OFFSET 0',
				[ $columnValue ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		if ($latestAttempt === null) {
			throw new ConfirmationRequestNotFound();
		}

		$this->throttle([ 'resendConfirmation', 'userId', $latestAttempt['user_id'] ], 1, (60 * 60 * 6));
		$this->throttle([ 'resendConfirmation', $this->getIpAddress() ], 4, (60 * 60 * 24 * 7), 2);

		$this->createConfirmationRequest(
			$latestAttempt['user_id'],
			$latestAttempt['email'],
			$callback
		);
	}

	/**
     * Инициирует запрос на сброс пароля для пользователя с указанным адресом электронной почты
     *
     * Функция обратного вызова должна иметь следующую подпись:
	 *
	 * `function ($selector, $token)`
     *
     * Обе части информации должны быть отправлены пользователю, как правило, встроены в ссылку.
     *
     * Когда пользователь хочет перейти ко второму этапу сброса пароля, снова потребуются обе части
	 *
	 * @param string $email адрес электронной почты пользователя, который хочет запросить сброс пароля
	 * @param callable $callback функция, которая отправляет пользователю информацию для сброса пароля
	 * @param int|null $requestExpiresAfter (необязательно) интервал в секундах, по истечении которого запрос должен истечь
	 * @param int|null $maxOpenRequests (необязательно) максимальное количество неистекших и неиспользованных запросов на пользователя
	 * @throws InvalidEmailException если адрес электронной почты недействителен или не может быть найден
	 * @throws EmailNotVerifiedException если адрес электронной почты еще не был подтвержден по электронной почте
	 * @throws ResetDisabledException если пользователь отключил сброс пароля для своей учетной записи
	 * @throws TooManyRequestsException если количество разрешенных попыток / запросов было превышено
	 * @throws AuthError если возникла внутренняя проблема
	 *
	 * @see canResetPasswordOrThrow
	 * @see canResetPassword
	 * @see resetPassword
	 * @see resetPasswordAndSignIn
	 */
	public function forgotPassword($email, callable $callback, $requestExpiresAfter = null, $maxOpenRequests = null) {
		$email = self::validateEmailAddress($email);

		$this->throttle([ 'enumerateUsers', $this->getIpAddress() ], 1, (60 * 60), 75);

		if ($requestExpiresAfter === null) {
			// использовать шесть часов по умолчанию
			$requestExpiresAfter = 60 * 60 * 6;
		}
		else {
			$requestExpiresAfter = (int) $requestExpiresAfter;
		}

		if ($maxOpenRequests === null) {
			// использовать два запроса на пользователя по умолчанию
			$maxOpenRequests = 2;
		}
		else {
			$maxOpenRequests = (int) $maxOpenRequests;
		}

		$userData = $this->getUserDataByEmailAddress(
			$email,
			[ 'id', 'verified', 'resettable' ]
		);

		// убедитесь, что учетная запись была проверена, прежде чем инициировать сброс пароля
		if ((int) $userData['verified'] !== 1) {
			throw new EmailNotVerifiedException();
		}

		// не разрешать сброс пароля, если пользователь явно отключил эту функцию
		if ((int) $userData['resettable'] !== 1) {
			throw new ResetDisabledException();
		}

		$openRequests = $this->throttling ? (int) $this->getOpenPasswordResetRequests($userData['id']) : 0;

		if ($openRequests < $maxOpenRequests) {
			$this->throttle([ 'requestPasswordReset', $this->getIpAddress() ], 4, (60 * 60 * 24 * 7), 2);
			$this->throttle([ 'requestPasswordReset', 'user', $userData['id'] ], 4, (60 * 60 * 24 * 7), 2);

			$this->createPasswordResetRequest($userData['id'], $requestExpiresAfter, $callback);
		}
		else {
			throw new TooManyRequestsException('', $requestExpiresAfter);
		}
	}

	/**
	 * Аутентифицирует существующего пользователя
	 *
	 * @param string $password пароль пользователя
	 * @param string|null $email (необязательно) адрес электронной почты пользователя
	 * @param string|null $username (необязательно) имя пользователя
	 * @param int|null $rememberDuration (необязательно) время в секундах, в течение которого пользователь остается в системе («запомни меня»)
	 * @param callable|null $onBeforeSuccess (необязательно) функция, которая получает идентификатор пользователя в качестве единственного параметра и выполняется до успешной аутентификации; должен вернуть true для продолжения или false для отмены
	 * @throws InvalidEmailException если адрес электронной почты недействителен или не может быть найден
	 * @throws UnknownUsernameException если была сделана попытка аутентификации с несуществующим именем пользователя
	 * @throws AmbiguousUsernameException если была сделана попытка аутентификации с неоднозначным именем пользователя
	 * @throws InvalidPasswordException если пароль был недействителен
	 * @throws EmailNotVerifiedException если адрес электронной почты еще не был подтвержден по электронной почте с подтверждением
	 * @throws AttemptCancelledException если попытка была отменена предоставленным обратным вызовом, который выполняется до успеха
	 * @throws TooManyRequestsException если количество разрешенных попыток/запросов было превышено
	 * @throws AuthError если возникла внутренняя проблема
	 */
	private function authenticateUserInternal($password, $email = null, $username = null, $rememberDuration = null, callable $onBeforeSuccess = null) {
		$this->throttle([ 'enumerateUsers', $this->getIpAddress() ], 1, (60 * 60), 75);
		$this->throttle([ 'attemptToLogin', $this->getIpAddress() ], 4, (60 * 60), 5, true);

		$columnsToFetch = [ 'id', 'email', 'password', 'verified', 'username', 'status', 'roles_mask', 'force_logout' ];

		if ($email !== null) {
			$email = self::validateEmailAddress($email);

			// попытаться найти информацию об учетной записи, используя указанный адрес электронной почты
			$userData = $this->getUserDataByEmailAddress(
				$email,
				$columnsToFetch
			);
		}
		elseif ($username !== null) {
			$username = \trim($username);

			// попытаться найти информацию об учетной записи, используя указанное имя пользователя
			$userData = $this->getUserDataByUsername(
				$username,
				$columnsToFetch
			);
		}
		// если ни адрес электронной почты, ни имя пользователя не были предоставлены
		else {
			// не можем здесь ничего сделать, потому что вызов метода был недопустимым
			throw new EmailOrUsernameRequiredError();
		}

		$password = self::validatePassword($password);

		if (\password_verify($password, $userData['password'])) {
			// если пароль необходимо повторно хешировать, нужно идти в ногу с совершенствованием методов взлома паролей
			if (\password_needs_rehash($userData['password'], \PASSWORD_DEFAULT)) {
				// создать новый хеш из пароля и обновить его в базе данных
				$this->updatePasswordInternal($userData['id'], $password);
			}

			if ((int) $userData['verified'] === 1) {
				if (!isset($onBeforeSuccess) || (\is_callable($onBeforeSuccess) && $onBeforeSuccess($userData['id']) === true)) {
					$this->onLoginSuccessful($userData['id'], $userData['email'], $userData['username'], $userData['status'], $userData['roles_mask'], $userData['force_logout'], false);

					// продолжить поддерживать старый формат параметров
					if ($rememberDuration === true) {
						$rememberDuration = 60 * 60 * 24 * 28;
					}
					elseif ($rememberDuration === false) {
						$rememberDuration = null;
					}

					if ($rememberDuration !== null) {
						$this->createRememberDirective($userData['id'], $rememberDuration);
					}

					return;
				}
				else {
					$this->throttle([ 'attemptToLogin', $this->getIpAddress() ], 4, (60 * 60), 5, false);

					if (isset($email)) {
						$this->throttle([ 'attemptToLogin', 'email', $email ], 500, (60 * 60 * 24), null, false);
					}
					elseif (isset($username)) {
						$this->throttle([ 'attemptToLogin', 'username', $username ], 500, (60 * 60 * 24), null, false);
					}

					throw new AttemptCancelledException();
				}
			}
			else {
				throw new EmailNotVerifiedException();
			}
		}
		else {
			$this->throttle([ 'attemptToLogin', $this->getIpAddress() ], 4, (60 * 60), 5, false);

			if (isset($email)) {
				$this->throttle([ 'attemptToLogin', 'email', $email ], 500, (60 * 60 * 24), null, false);
			}
			elseif (isset($username)) {
				$this->throttle([ 'attemptToLogin', 'username', $username ], 500, (60 * 60 * 24), null, false);
			}

			// если не можем аутентифицировать пользователя из-за неправильного пароля
			throw new InvalidPasswordException();
		}
	}

	/**
     * Возвращает запрошенные данные пользователя для учетной записи с указанным адресом электронной почты (если есть)
     *
     * Вы никогда не должны передавать ненадежный ввод в параметр, который принимает список столбцов.
	 *
	 * @param string $email адрес электронной почты для поиска
	 * @param array $requestedColumns столбцы для запроса из записи пользователя
	 * @return array данные пользователя (если была найдена учетная запись)
	 * @throws InvalidEmailException если адрес электронной почты не может быть найден
	 * @throws AuthError если возникла внутренняя проблема
	 */
	private function getUserDataByEmailAddress($email, array $requestedColumns) {
		try {
			$projection = \implode(', ', $requestedColumns);
			$userData = $this->db->selectRow(
				'SELECT ' . $projection . ' FROM ' . $this->makeTableName('users') . ' WHERE email = ?',
				[ $email ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		if (!empty($userData)) {
			return $userData;
		}
		else {
			throw new InvalidEmailException();
		}
	}

	/**
	 * Возвращает количество открытых запросов на сброс пароля указанным пользователем.
	 *
	 * @param int $userId ID пользователя для проверки запросов на
	 * @return int количество открытых запросов на сброс пароля
	 * @throws AuthError если возникла внутренняя проблема
	 */
	private function getOpenPasswordResetRequests($userId) {
		try {
			$requests = $this->db->selectValue(
				'SELECT COUNT(*) FROM ' . $this->makeTableName('users_resets') . ' WHERE user = ? AND expires > ?',
				[
					$userId,
					\time()
				]
			);

			if (!empty($requests)) {
				return $requests;
			}
			else {
				return 0;
			}
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}
	}

	/**
     * Создает новый запрос на сброс пароля
     *
     * Функция обратного вызова должна иметь следующую подпись:
	 *
	 * `function ($selector, $token)`
     *
     * Обе части информации должны быть отправлены пользователю, как правило, встроены в ссылку.
     *
     * Когда пользователь хочет перейти ко второму этапу сброса пароля, снова потребуются обе части
	 *
	 * @param int $userId ID пользователя, который запросил сброс
	 * @param int $expiresAfter интервал в секундах, по истечении которого запрос должен истечь
	 * @param callable $callback функция, которая отправляет пользователю информацию для сброса пароля
	 * @throws AuthError если возникла внутренняя проблема
	 */
	private function createPasswordResetRequest($userId, $expiresAfter, callable $callback) {
		$selector = self::createRandomString(20);
		$token = self::createRandomString(20);
		$tokenHashed = \password_hash($token, \PASSWORD_DEFAULT);
		$expiresAt = \time() + $expiresAfter;

		try {
			$this->db->insert(
				$this->makeTableNameComponents('users_resets'),
				[
					'user' => $userId,
					'selector' => $selector,
					'token' => $tokenHashed,
					'expires' => $expiresAt
				]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		if (\is_callable($callback)) {
			$callback($selector, $token);
		}
		else {
			throw new MissingCallbackError();
		}
	}

	/**
	 * Сбрасывает пароль для конкретной учетной записи, указав правильную пару селектор/токен
	 *
	 * Пара селектор/токен должна быть сгенерирована ранее путем вызова {@see forgotPassword}
	 *
	 * @param string $selector селектор из пары селектор/токен
	 * @param string $token токен из пары селектор/токен
	 * @param string $newPassword новый пароль для учетной записи
	 * @return string[] массив с идентификатором пользователя в индексе `id` и адресом электронной почты пользователя в индексе` email`
	 * @throws InvalidSelectorTokenPairException если либо селектор, либо токен был неправильным
	 * @throws TokenExpiredException если срок действия токена уже истек
	 * @throws ResetDisabledException если пользователь явно отключил сброс пароля для своей учетной записи
	 * @throws InvalidPasswordException если новый пароль был недействителен
	 * @throws TooManyRequestsException если количество разрешенных попыток/запросов было превышено
	 * @throws AuthError если возникла внутренняя проблема
	 *
	 * @see forgotPassword
	 * @see canResetPasswordOrThrow
	 * @see canResetPassword
	 * @see resetPasswordAndSignIn
	 */
	public function resetPassword($selector, $token, $newPassword) {
		$this->throttle([ 'resetPassword', $this->getIpAddress() ], 5, (60 * 60), 10);
		$this->throttle([ 'resetPassword', 'selector', $selector ], 3, (60 * 60), 10);
		$this->throttle([ 'resetPassword', 'token', $token ], 3, (60 * 60), 10);

		try {
			$resetData = $this->db->selectRow(
				'SELECT a.id, a.user, a.token, a.expires, b.email, b.resettable FROM ' . $this->makeTableName('users_resets') . ' AS a JOIN ' . $this->makeTableName('users') . ' AS b ON b.id = a.user WHERE a.selector = ?',
				[ $selector ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		if (!empty($resetData)) {
			if ((int) $resetData['resettable'] === 1) {
				if (\password_verify($token, $resetData['token'])) {
					if ($resetData['expires'] >= \time()) {
						$newPassword = self::validatePassword($newPassword);
						$this->updatePasswordInternal($resetData['user'], $newPassword);
						$this->forceLogoutForUserById($resetData['user']);

						try {
							$this->db->delete(
								$this->makeTableNameComponents('users_resets'),
								[ 'id' => $resetData['id'] ]
							);
						}
						catch (Error $e) {
							throw new DatabaseError($e->getMessage());
						}

						return [
							'id' => $resetData['user'],
							'email' => $resetData['email']
						];
					}
					else {
						throw new TokenExpiredException();
					}
				}
				else {
					throw new InvalidSelectorTokenPairException();
				}
			}
			else {
				throw new ResetDisabledException();
			}
		}
		else {
			throw new InvalidSelectorTokenPairException();
		}
	}

	/**
	 * Сбрасывает пароль для конкретной учетной записи, указав правильную пару селектор/токен
	 *
	 * Пара селектор/токен должна быть сгенерирована ранее путем вызова {@see forgotPassword}
	 *
	 * Пользователь будет автоматически авторизован, если эта операция прошла успешно.
	 *
	 * @param string $selector селектор из пары селектор/токен
	 * @param string $token токен из пары селектор/токен
	 * @param string $newPassword новый пароль для учетной записи
	 * @param int|null $rememberDuration (необязательно) время в секундах, в течение которого пользователь остается в системе («запомни меня»)
	 * @return string[] массив с идентификатором пользователя в индексе `id` и адресом электронной почты пользователя в индексе` email`
     * @throws InvalidSelectorTokenPairException если либо селектор, либо токен был неправильным
     * @throws TokenExpiredException если срок действия токена уже истек
     * @throws ResetDisabledException если пользователь отключил сброс пароля для своей учетной записи
     * @throws InvalidPasswordException если новый пароль был недействителен
     * @throws TooManyRequestsException если количество разрешенных попыток/запросов было превышено
	 * @throws AuthError если возникла внутренняя проблема
	 *
	 * @see forgotPassword
	 * @see canResetPasswordOrThrow
	 * @see canResetPassword
	 * @see resetPassword
	 */
	public function resetPasswordAndSignIn($selector, $token, $newPassword, $rememberDuration = null) {
		$idAndEmail = $this->resetPassword($selector, $token, $newPassword);

		if (!$this->isLoggedIn()) {
			$idAndEmail['email'] = self::validateEmailAddress($idAndEmail['email']);

			$userData = $this->getUserDataByEmailAddress(
				$idAndEmail['email'],
				[ 'username', 'status', 'roles_mask', 'force_logout' ]
			);

			$this->onLoginSuccessful($idAndEmail['id'], $idAndEmail['email'], $userData['username'], $userData['status'], $userData['roles_mask'], $userData['force_logout'], true);

			if ($rememberDuration !== null) {
				$this->createRememberDirective($idAndEmail['id'], $rememberDuration);
			}
		}

		return $idAndEmail;
	}

	/**
     * Проверьте, можно ли использовать поставляемую пару селектор/токен для сброса пароля.
     *
     * Пароль можно сбросить, используя предоставленную информацию, если этот метод *не* вызывает исключение.
	 *
	 * Пара селектор/токен должна быть сгенерирована ранее путем вызова {@see forgotPassword}
	 *
	 * @param string $selector селектор из пары селектор/токен
	 * @param string $token токен из пары селектор/токен
	 * @throws InvalidSelectorTokenPairException если либо селектор, либо токен был неправильным
	 * @throws TokenExpiredException если срок действия токена уже истек
	 * @throws ResetDisabledException если пользователь отключил сброс пароля для своей учетной записи
	 * @throws TooManyRequestsException если количество разрешенных попыток/запросов было превышено
	 * @throws AuthError если возникла внутренняя проблема
	 *
	 * @see forgotPassword
	 * @see canResetPassword
	 * @see resetPassword
	 * @see resetPasswordAndSignIn
	 */
	public function canResetPasswordOrThrow($selector, $token) {
		try {
			// намеренно передать не верный пароль, чтобы вызвать ожидаемую ошибку
			$this->resetPassword($selector, $token, null);

			// мы уже должны быть в одном из блоков `catch`, так что этого не ожидается
			throw new AuthError();
		}
		// если пароль - единственное, что недействительно
		catch (InvalidPasswordException $ignored) {
			// пароль можно сбросить
		}
		// если что-то еще не удалось (а также)
		catch (AuthException $e) {
			// повторно выбросить исключение
			throw $e;
		}
	}

	/**
	 * Проверьте, можно ли использовать поставляемую пару селектор/токен для сброса пароля.
	 *
	 * Пара селектор/токен должна быть сгенерирована ранее путем вызова {@see forgotPassword}
	 *
	 * @param string $selector селектор из пары селектор / токен
	 * @param string $token токен из пары селектор / токен
	 * @return bool можно ли сбросить пароль, используя предоставленную информацию
	 * @throws AuthError если возникла внутренняя проблема
	 *
	 * @see forgotPassword
	 * @see canResetPasswordOrThrow
	 * @see resetPassword
	 * @see resetPasswordAndSignIn
	 */
	public function canResetPassword($selector, $token) {
		try {
			$this->canResetPasswordOrThrow($selector, $token);

			return true;
		}
		catch (AuthException $e) {
			return false;
		}
	}

	/**
	 * Устанавливает, следует ли разрешить сброс пароля для учетной записи текущего пользователя, вошедшего в систему.
	 *
	 * @param bool $enabled должен ли быть разрешен сброс пароля для учетной записи пользователя
	 * @throws NotLoggedInException если пользователь в настоящее время не вошел в систему
	 * @throws AuthError если возникла внутренняя проблема
	 */
	public function setPasswordResetEnabled($enabled) {
		$enabled = (bool) $enabled;

		if ($this->isLoggedIn()) {
			try {
				$this->db->update(
					$this->makeTableNameComponents('users'),
					[
						'resettable' => $enabled ? 1 : 0
					],
					[
						'id' => $this->getUserId()
					]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}
		}
		else {
			throw new NotLoggedInException();
		}
	}

	/**
	 * Возвращает, разрешен ли сброс пароля для учетной записи текущего пользователя, вошедшего в систему.
	 *
	 * @return bool
	 * @throws NotLoggedInException если пользователь в настоящее время не вошел в систему
	 * @throws AuthError если возникла внутренняя проблема
	 */
	public function isPasswordResetEnabled() {
		if ($this->isLoggedIn()) {
			try {
				$enabled = $this->db->selectValue(
					'SELECT resettable FROM ' . $this->makeTableName('users') . ' WHERE id = ?',
					[ $this->getUserId() ]
				);

				return (int) $enabled === 1;
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}
		}
		else {
			throw new NotLoggedInException();
		}
	}

	/**
	 * Возвращает, вошел ли пользователь в систему, читая данные из сеанса.
	 *
	 * @return boolean вошел ли пользователь в систему или нет
	 */
	public function isLoggedIn() {
		return isset($_SESSION) && isset($_SESSION[self::SESSION_FIELD_LOGGED_IN]) && $_SESSION[self::SESSION_FIELD_LOGGED_IN] === true;
	}

	/**
	 * Сокращение/псевдоним для ´isLoggedIn()´
	 *
	 * @return boolean
	 */
	public function check() {
		return $this->isLoggedIn();
	}

	/**
	 * Возвращает идентификатор пользователя, вошедшего в систему, путем чтения из сеанса
	 *
	 * @return int user ID
	 */
	public function getUserId() {
		if (isset($_SESSION) && isset($_SESSION[self::SESSION_FIELD_USER_ID])) {
			return $_SESSION[self::SESSION_FIELD_USER_ID];
		}
		else {
			return null;
		}
	}

	/**
	 * Shorthand/alias for {@see getUserId}
	 *
	 * @return int
	 */
	public function id() {
		return $this->getUserId();
	}

	/**
	 * Возвращает адрес электронной почты пользователя, вошедшего в систему, путем чтения из сеанса
	 *
	 * @return string адрес электронной почты
	 */
	public function getEmail() {
		if (isset($_SESSION) && isset($_SESSION[self::SESSION_FIELD_EMAIL])) {
			return $_SESSION[self::SESSION_FIELD_EMAIL];
		}
		else {
			return null;
		}
	}

	/**
	 * Возвращает отображаемое имя текущего вошедшего в систему пользователя путем чтения из сеанса
	 *
	 * @return string отображаемое имя
	 */
	public function getUsername() {
		if (isset($_SESSION) && isset($_SESSION[self::SESSION_FIELD_USERNAME])) {
			return $_SESSION[self::SESSION_FIELD_USERNAME];
		}
		else {
			return null;
		}
	}

	/**
	 * Возвращает статус текущего вошедшего в систему пользователя путем чтения из сеанса
	 *
	 * @return int статус как одна из констант из класса {@see Status}
	 */
	public function getStatus() {
		if (isset($_SESSION) && isset($_SESSION[self::SESSION_FIELD_STATUS])) {
			return $_SESSION[self::SESSION_FIELD_STATUS];
		}
		else {
			return null;
		}
	}

	/**
	 * Возвращает, находится ли текущий авторизованный пользователь в "нормальном" состоянии.
	 *
	 * @return bool
	 *
	 * @see Status
	 * @see Auth::getStatus
	 */
	public function isNormal() {
		return $this->getStatus() === Status::NORMAL;
	}

	/**
	 * Возвращает, находится ли текущий авторизованный пользователь в состоянии "заархивирован".
	 *
	 * @return bool
	 *
	 * @see Status
	 * @see Auth::getStatus
	 */
	public function isArchived() {
		return $this->getStatus() === Status::ARCHIVED;
	}

	/**
	 * Возвращает, находится ли текущий авторизованный пользователь в "забаненном" состоянии.
	 *
	 * @return bool
	 *
	 * @see Status
	 * @see Auth::getStatus
	 */
	public function isBanned() {
		return $this->getStatus() === Status::BANNED;
	}

	/**
	 * Возвращает, находится ли текущий авторизованный пользователь в "заблокированном" состоянии.
	 *
	 * @return bool
	 *
	 * @see Status
	 * @see Auth::getStatus
	 */
	public function isLocked() {
		return $this->getStatus() === Status::LOCKED;
	}

	/**
	 * Возвращает, находится ли текущий вошедший в систему пользователь в состоянии «ожидает проверки».
	 *
	 * @return bool
	 *
	 * @see Status
	 * @see Auth::getStatus
	 */
	public function isPendingReview() {
		return $this->getStatus() === Status::PENDING_REVIEW;
	}

	/**
	 * Возвращает, находится ли текущий вошедший в систему пользователь в "приостановленном" состоянии.
	 *
	 * @return bool
	 *
	 * @see Status
	 * @see Auth::getStatus
	 */
	public function isSuspended() {
		return $this->getStatus() === Status::SUSPENDED;
	}

	/**
	 * Возвращает, имеет ли текущий вошедший в систему пользователь указанную роль.
	 *
	 * @param int $role роль как одна из констант класса {@see Role}
	 * @return bool
	 *
	 * @see Role
	 */
	public function hasRole($role) {
		if (empty($role) || !\is_numeric($role)) {
			return false;
		}

		if (isset($_SESSION) && isset($_SESSION[self::SESSION_FIELD_ROLES])) {
			$role = (int) $role;

			return (((int) $_SESSION[self::SESSION_FIELD_ROLES]) & $role) === $role;
		}
		else {
			return false;
		}
	}

	/**
	 * Возвращает, имеет ли текущий вошедший в систему пользователь *любую* из указанных ролей.
	 *
	 * @param int[] ...$roles роли как константы из класса {@see Role}
	 * @return bool
	 *
	 * @see Role
	 */
	public function hasAnyRole(...$roles) {
		foreach ($roles as $role) {
			if ($this->hasRole($role)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Возвращает, имеет ли текущий вошедший в систему пользователь *все* указанные роли.
	 *
	 * @param int[] ...$roles роли как константы из класса {@see Role}
	 * @return bool
	 *
	 * @see Role
	 */
	public function hasAllRoles(...$roles) {
		foreach ($roles as $role) {
			if (!$this->hasRole($role)) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Возвращает массив ролей пользователя, сопоставляя числовые значения с их описательными именами.
	 *
	 * @return array
	 */
	public function getRoles() {
		return \array_filter(
			Role::getMap(),
			[ $this, 'hasRole' ],
			\ARRAY_FILTER_USE_KEY
		);
	}

	/**
	 * Возвращает, запомнился ли текущий авторизованный пользователь долгоживущим файлом cookie.
	 *
	 * @return bool
	 */
	public function isRemembered() {
		if (isset($_SESSION) && isset($_SESSION[self::SESSION_FIELD_REMEMBERED])) {
			return $_SESSION[self::SESSION_FIELD_REMEMBERED];
		}
		else {
			return null;
		}
	}

	/**
	 * Возвращает текущий IP-адрес пользователя.
	 *
	 * @return string IP-адрес (IPv4 или IPv6)
	 */
	public function getIpAddress() {
		return $this->ipAddress;
	}

	/**
     * Выполняет дросселирование или ограничение скорости с использованием алгоритма маркерного ведра (алгоритм обратного дырявого ведра)
	 *
	 * @param array $criteria отдельные критерии, которые вместе описывают регулируемый ресурс
	 * @param int $supply количество единиц, предоставляемых за интервал (> = 1)
	 * @param int $interval интервал (в секундах), на который предоставляется подача (> = 5)
	 * @param int|null $burstiness (необязательно) допустимая степень вариации или неравномерности во время пиков (> = 1)
	 * @param bool|null $simulated (необязательно) следует ли имитировать пробный запуск вместо фактического потребления запрошенных единиц
	 * @param int|null $cost (необязательно) количество единиц для запроса (> = 1)
	 * @param bool|null $force (необязательно) применять ли регулирование локально (с помощью этого вызова), даже если регулирование было отключено глобально (на экземпляре с помощью параметра конструктора)
	 * @return float количество единиц, оставшихся от запаса
	 * @throws TooManyRequestsException если фактический спрос превысил обозначенное предложение
	 * @throws AuthError если возникла внутренняя проблема
	 */
	public function throttle(array $criteria, $supply, $interval, $burstiness = null, $simulated = null, $cost = null, $force = null) {
		// проверьте предоставленные параметры и при необходимости установите соответствующие значения по умолчанию
		$force = ($force !== null) ? (bool) $force : false;

		if (!$this->throttling && !$force) {
			return $supply;
		}

		// сгенерировать уникальный ключ для сегмента (состоящий из 44 или менее символов ASCII)
		$key = Base64::encodeUrlSafeWithoutPadding(
			\hash(
				'sha256',
				\implode("\n", $criteria),
				true
			)
		);

		// проверьте предоставленные параметры и при необходимости установите соответствующие значения по умолчанию
		$burstiness = ($burstiness !== null) ? (int) $burstiness : 1;
		$simulated = ($simulated !== null) ? (bool) $simulated : false;
		$cost = ($cost !== null) ? (int) $cost : 1;

		$now = \time();

		$capacity = $burstiness * (int) $supply;

		// рассчитать скорость пополнения (в секунду)
		$bandwidthPerSecond = (int) $supply / (int) $interval;

		try {
			$bucket = $this->db->selectRow(
				'SELECT tokens, replenished_at FROM ' . $this->makeTableName('users_throttling') . ' WHERE bucket = ?',
				[ $key ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		if ($bucket === null) {
			$bucket = [];
		}

		// инициализировать количество токенов
		$bucket['tokens'] = isset($bucket['tokens']) ? (float) $bucket['tokens'] : (float) $capacity;
		// инициализировать время последнего пополнения (как временная метка Unix в секундах)
		$bucket['replenished_at'] = isset($bucket['replenished_at']) ? (int) $bucket['replenished_at'] : $now;

		// пополнить по мере необходимости
		$secondsSinceLastReplenishment = \max(0, $now - $bucket['replenished_at']);
		$tokensToAdd = $secondsSinceLastReplenishment * $bandwidthPerSecond;
		$bucket['tokens'] = \min((float) $capacity, $bucket['tokens'] + $tokensToAdd);
		$bucket['replenished_at'] = $now;

		$accepted = $bucket['tokens'] >= $cost;

		if (!$simulated) {
			if ($accepted) {
				// удалить запрошенное количество токенов
				$bucket['tokens'] = \max(0, $bucket['tokens'] - $cost);
			}

			// установить самое раннее время, после которого сегмент *может* быть удален (как временная метка Unix в секундах)
			$bucket['expires_at'] = $now + \floor($capacity / $bandwidthPerSecond * 2);

			// объединить с базой данных
			try {
				$affected = $this->db->update(
					$this->makeTableNameComponents('users_throttling'),
					$bucket,
					[ 'bucket' => $key ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}

			if ($affected === 0) {
				$bucket['bucket'] = $key;

				try {
					$this->db->insert(
						$this->makeTableNameComponents('users_throttling'),
						$bucket
					);
				}
				catch (IntegrityConstraintViolationException $ignored) {}
				catch (Error $e) {
					throw new DatabaseError($e->getMessage());
				}
			}
		}

		if ($accepted) {
			return $bucket['tokens'];
		}
		else {
			$tokensMissing = $cost - $bucket['tokens'];
			$estimatedWaitingTimeSeconds = \ceil($tokensMissing / $bandwidthPerSecond);

			throw new TooManyRequestsException('', $estimatedWaitingTimeSeconds);
		}
	}

	/**
	 * Возвращает компонент, который можно использовать для административных задач.
	 *
	 * Доступ предоставляется к этому интерфейсу только авторизованным пользователям (ограничен собственным контролем доступа)
	 *
	 * @return Administration
	 */
	public function admin() {
		return new Administration($this->db, $this->dbTablePrefix, $this->dbSchema);
	}

	/**
	 * Создает UUID v4 согласно RFC 4122
	 *
	 * UUID содержит 128 бит данных (где 122 случайные), то есть 36 символов.
	 *
	 */
	public static function createUuid() {
		$data = \openssl_random_pseudo_bytes(16);

		// установить версию 0100
		$data[6] = \chr(\ord($data[6]) & 0x0f | 0x40);
		// установить биты 6-7, 10
		$data[8] = \chr(\ord($data[8]) & 0x3f | 0x80);

		return \vsprintf('%s%s-%s-%s-%s-%s%s%s', \str_split(\bin2hex($data), 4));
	}

	/**
	 * Создает уникальное имя файла cookie для данного дескриптора на основе предоставленного начального числа.
	 *
	 * @param string $descriptor коротое описание
	 * @param string|null $seed (необязательно) данные для детерминированного создания имени
	 * @return string
	 */
	public static function createCookieName($descriptor, $seed = null) {
		// использовать предоставленное начальное число или текущее время UNIX в секундах
		$seed = ($seed !== null) ? $seed : \time();

		foreach (self::COOKIE_PREFIXES as $cookiePrefix) {
			// если семя содержит определенный префикс cookie
			if (\strpos($seed, $cookiePrefix) === 0) {
				// добавить тот же префикс к дескриптору
				$descriptor = $cookiePrefix . $descriptor;
			}
		}

		// сгенерировать уникальный токен на основе имени (пространства) этой библиотеки
		$token = Base64::encodeUrlSafeWithoutPadding(
			\md5(
				__NAMESPACE__ . "\n" . $seed,
				true
			)
		);

		return $descriptor . '_' . $token;
	}

	/**
	 * Создает уникальное имя файла cookie для функции «запомнить меня»
	 *
	 * @param string|null $sessionName (необязательно) имя сеанса
	 * @return string
	 */
	public static function createRememberCookieName($sessionName = null) {
		return self::createCookieName(
			'remember',
			($sessionName !== null) ? $sessionName : \session_name()
		);
	}

	/**
	 * Возвращает селектор потенциально существующей локально директивы
     *
	 * @return string|null
	 */
	private function getRememberDirectiveSelector() {
		if (isset($_COOKIE[$this->rememberCookieName])) {
			$selectorAndToken = \explode(self::COOKIE_CONTENT_SEPARATOR, $_COOKIE[$this->rememberCookieName], 2);

			return $selectorAndToken[0];
		}
		else {
			return null;
		}
	}

	/**
	 * Возвращает дату истечения срока дерективы.
	 *
	 * @return int|null
	 */
	private function getRememberDirectiveExpiry() {
		// если пользователь в настоящее время вошел в систему
		if ($this->isLoggedIn()) {
			// определить селектор любой существующей в настоящее время директивы запоминания
			$existingSelector = $this->getRememberDirectiveSelector();

			// если в настоящее время существует директива запоминания, селектор которой мы только что получили
			if (isset($existingSelector)) {
				// получить дату истечения срока действия для данного селектора
				$existingExpiry = $this->db->selectValue(
					'SELECT expires FROM ' . $this->makeTableName('users_remembered') . ' WHERE selector = ? AND user = ?',
					[
						$existingSelector,
						$this->getUserId()
					]
				);

				// если срок годности был найден
				if (isset($existingExpiry)) {
					// вернуть дату
					return (int) $existingExpiry;
				}
			}
		}

		return null;
	}

}
