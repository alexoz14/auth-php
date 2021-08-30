<?php

namespace Delight\Auth;

use Delight\Base64\Base64;
use Delight\Cookie\Session;
use Delight\Db\PdoDatabase;
use Delight\Db\PdoDsn;
use Delight\Db\Throwable\Error;
use Delight\Db\Throwable\IntegrityConstraintViolationException;

/**
 * Абстрактный базовый класс для компонентов, реализующих управление пользователями
 *
 * @internal
 */
abstract class UserManager {

	/** @var string поле сеанса, чтобы узнать, вошел ли клиент в систему в данный момент*/
	const SESSION_FIELD_LOGGED_IN = 'auth_logged_in';
	/** @var string поле сеанса для идентификатора пользователя, который в настоящее время вошел в систему (если есть) */
	const SESSION_FIELD_USER_ID = 'auth_user_id';
	/** @var string поле сеанса для адреса электронной почты пользователя, который в настоящее время вошел в систему (если есть) */
	const SESSION_FIELD_EMAIL = 'auth_email';
	/** @var string поле сеанса для отображаемого имени (если есть) пользователя, который в настоящее время вошел в систему (если есть) */
	const SESSION_FIELD_USERNAME = 'auth_username';
	/** @var string поле сеанса для статуса пользователя, который в настоящее время вошел в систему (если есть), как одна из констант из класса {@see Status} */
	const SESSION_FIELD_STATUS = 'auth_status';
	/** @var string поле сеанса для ролей пользователя, который в данный момент вошел в систему (если есть), в виде битовой маски с использованием констант из класса {@see Role} */
	const SESSION_FIELD_ROLES = 'auth_roles';
	/** @var string поле сеанса, указывающее, был ли запомнен пользователь, который в настоящее время вошел в систему (если есть) (вместо того, чтобы он прошел активную аутентификацию) */
	const SESSION_FIELD_REMEMBERED = 'auth_remembered';
	/** @var string поле сеанса для метки времени UNIX в секундах последней ресинхронизации данных сеанса с его официальным источником в базе данных */
	const SESSION_FIELD_LAST_RESYNC = 'auth_last_resync';
	/** @var string поле сеанса для счетчика, отслеживающего принудительные выходы из системы, которые необходимо выполнить в текущем сеансе */
	const SESSION_FIELD_FORCE_LOGOUT = 'auth_force_logout';

	/** @var PdoDatabase соединение с базой данных для работы */
	protected $db;
	/** @var string|null имя схемы для всех таблиц базы данных, используемых этим компонентом */
	protected $dbSchema;
	/** @var string префикс для имен всех таблиц базы данных, используемых этим компонентом */
	protected $dbTablePrefix;

	/**
	 * Создает случайную строку с заданной максимальной длиной
	 *
	 * С параметром по умолчанию вывод должен содержать как минимум столько же случайности, сколько UUID.
	 *
	 * @param int $maxLength максимальная длина выходной строки (целое кратное 4)
	 * @return string новая случайная строка
	 */
	public static function createRandomString($maxLength = 24) {
		// вычислить, сколько байтов случайности нам нужно для указанной длины строки
		$bytes = \floor((int) $maxLength / 4) * 3;

		// получить случайные данные
		$data = \openssl_random_pseudo_bytes($bytes);

		// вернуть результат в кодировке Base64
		return Base64::encodeUrlSafe($data);
	}

	/**
	 * @param PdoDatabase|PdoDsn|\PDO $databaseConnection соединение с базой данных для работы
	 * @param string|null $dbTablePrefix (необязательно) префикс для имен всех таблиц базы данных, используемых этим компонентом
	 * @param string|null $dbSchema (необязательно) имя схемы для всех таблиц базы данных, используемых этим компонентом
	 */
	protected function __construct($databaseConnection, $dbTablePrefix = null, $dbSchema = null) {
		if ($databaseConnection instanceof PdoDatabase) {
			$this->db = $databaseConnection;
		}
		elseif ($databaseConnection instanceof PdoDsn) {
			$this->db = PdoDatabase::fromDsn($databaseConnection);
		}
		elseif ($databaseConnection instanceof \PDO) {
			$this->db = PdoDatabase::fromPdo($databaseConnection, true);
		}
		else {
			$this->db = null;

			throw new \InvalidArgumentException('The database connection must be an instance of either `PdoDatabase`, `PdoDsn` or `PDO`');
		}

		$this->dbSchema = $dbSchema !== null ? (string) $dbSchema : null;
		$this->dbTablePrefix = (string) $dbTablePrefix;
	}

	/**
	 * Создает нового пользователя
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
	 * @param bool $requireUniqueUsername нужно ли уникальность имени пользователя?
	 * @param string $email адрес электронной почты для регистрации
	 * @param string $password пароль для новой учетной записи
	 * @param string|null $username (необязательно) имя пользователя, которое будет отображаться
	 * @param callable|null $callback (необязательно) функция, которая отправляет пользователю электронное письмо с подтверждением
	 * @return int ID созданного пользователя (если есть)
	 * @throws InvalidEmailException если адрес электронной почты недействителен
	 * @throws InvalidPasswordException если пароль недействителен
	 * @throws UserAlreadyExistsException если пользователь с указанным адресом электронной почты уже существует
	 * @throws DuplicateUsernameException если было указано!, что имя пользователя должно быть уникальным "Дубликаты"
	 * @throws AuthError если возникла внутренняя проблема
	 *
	 * @see confirmEmail
	 * @see confirmEmailAndSignIn
	 */
	protected function createUserInternal($requireUniqueUsername, $email, $password, $username = null, callable $callback = null) {
		\ignore_user_abort(true);

		$email = self::validateEmailAddress($email);
		$password = self::validatePassword($password);

		$username = isset($username) ? \trim($username) : null;

		// если предоставленное имя пользователя является пустой строкой или состояло только из пробелов
		if ($username === '') {
			// на самом деле это означает, что нет имени пользователя
			$username = null;
		}

		//если нужно гарантировать уникальность имени пользователя
		if ($requireUniqueUsername) {
			// если имя пользователя действительно
			if ($username !== null) {
				// подсчитать количество пользователей, у которых уже есть указанное имя пользователя
				$occurrencesOfUsername = $this->db->selectValue(
					'SELECT COUNT(*) FROM ' . $this->makeTableName('users') . ' WHERE username = ?',
					[ $username ]
				);

				// если какой-либо пользователь с таким именем уже существует
				if ($occurrencesOfUsername > 0) {
					// отменить операцию и сообщить о нарушении данного требования
					throw new DuplicateUsernameException();
				}
			}
		}

		$password = \password_hash($password, \PASSWORD_DEFAULT);
		$verified = \is_callable($callback) ? 0 : 1;

		try {
			$this->db->insert(
				$this->makeTableNameComponents('users'),
				[
					'email' => $email,
					'password' => $password,
					'username' => $username,
					'verified' => $verified,
					'registered' => \time()
				]
			);
		}
		// if we have a duplicate entry
		catch (IntegrityConstraintViolationException $e) {
			throw new UserAlreadyExistsException();
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		$newUserId = (int) $this->db->getLastInsertId();

		if ($verified === 0) {
			$this->createConfirmationRequest($newUserId, $email, $callback);
		}

		return $newUserId;
	}

	/**
	 * Обновляет пароль данного пользователя, устанавливая его на новый указанный пароль
	 *
	 * @param int $userId ID пользователя, пароль которого необходимо обновить
	 * @param string $newPassword новый пароль
	 * @throws UnknownIdException если не найдено ни одного пользователя с указанным ID
	 * @throws AuthError если возникла внутренняя проблема
     */
	protected function updatePasswordInternal($userId, $newPassword) {
		$newPassword = \password_hash($newPassword, \PASSWORD_DEFAULT);

		try {
			$affected = $this->db->update(
				$this->makeTableNameComponents('users'),
				[ 'password' => $newPassword ],
				[ 'id' => $userId ]
			);

			if ($affected === 0) {
				throw new UnknownIdException();
			}
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}
	}

	/**
	 * Вызывается, когда пользователь успешно вошел в систему
	 *
	 * Это может произойти при стандартном входе в систему, с помощью функции «запомнить меня» или из-за выдачи себя за другое лицо со стороны администраторов.
	 *
	 * @param int $userId ID пользователя
	 * @param string $email адрес электронной почты пользователя
	 * @param string $username отображаемое имя (если есть) пользователя
	 * @param int $status статус пользователя как одна из констант класса {@see Status}
	 * @param int $roles роли пользователя в виде битовой маски с использованием констант из класса {@see Role}
	 * @param int $forceLogout счетчик, отслеживающий принудительные выходы из системы, которые необходимо выполнить в текущем сеансе
	 * @param bool $remembered запомнился ли пользователь (вместо активной аутентификации)
     * @throws AuthError если возникла внутренняя проблема
	 */
	protected function onLoginSuccessful($userId, $email, $username, $status, $roles, $forceLogout, $remembered) {
		// повторно сгенерировать идентификатор сеанса, чтобы предотвратить атаки фиксации сеанса (запрашивает запись cookie на клиенте)
		Session::regenerate(true);

		// сохранять данные пользователя в переменных сеанса, поддерживаемых этой библиотекой
		$_SESSION[self::SESSION_FIELD_LOGGED_IN] = true;
		$_SESSION[self::SESSION_FIELD_USER_ID] = (int) $userId;
		$_SESSION[self::SESSION_FIELD_EMAIL] = $email;
		$_SESSION[self::SESSION_FIELD_USERNAME] = $username;
		$_SESSION[self::SESSION_FIELD_STATUS] = (int) $status;
		$_SESSION[self::SESSION_FIELD_ROLES] = (int) $roles;
		$_SESSION[self::SESSION_FIELD_FORCE_LOGOUT] = (int) $forceLogout;
		$_SESSION[self::SESSION_FIELD_REMEMBERED] = $remembered;
		$_SESSION[self::SESSION_FIELD_LAST_RESYNC] = \time();
	}

	/**
	 * Возвращает запрошенные данные пользователя для учетной записи с указанным именем пользователя (если есть)
	 *
	 * Вы никогда не должны передавать не надежные параметры, которые принимают имя столбца.
	 *
	 * @param string $username имя пользователя для поиска
	 * @param array $requestedColumns столбцы для запроса записи пользователя
	 * @return array данные пользователя (если аккаунт был найден)
	 * @throws UnknownUsernameException если ни один пользователь с указанным именем не найден
	 * @throws AmbiguousUsernameException если найдено несколько пользователей с указанным именем
	 * @throws AuthError если возникла внутренняя проблема
	 */
	protected function getUserDataByUsername($username, array $requestedColumns) {
		try {
			$projection = \implode(', ', $requestedColumns);

			$users = $this->db->select(
				'SELECT ' . $projection . ' FROM ' . $this->makeTableName('users') . ' WHERE username = ? LIMIT 2 OFFSET 0',
				[ $username ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		if (empty($users)) {
			throw new UnknownUsernameException();
		}
		else {
			if (\count($users) === 1) {
				return $users[0];
			}
			else {
				throw new AmbiguousUsernameException();
			}
		}
	}

	/**
	 * Проверяем адрес электронной почты
	 *
	 * @param string $email адрес электронной почты для проверки
	 * @return string очищенный адрес электронной почты
	 * @throws InvalidEmailException если адрес электронной почты недействителен
	 */
	protected static function validateEmailAddress($email) {
		if (empty($email)) {
			throw new InvalidEmailException();
		}

		$email = \trim($email);

		if (!\filter_var($email, \FILTER_VALIDATE_EMAIL)) {
			throw new InvalidEmailException();
		}

		return $email;
	}

	/**
	 * Проверка пароля
	 *
	 * @param string $password пароль для проверки
	 * @return string дезинфицированный пароль
	 * @throws InvalidPasswordException если пароль недействителен
	 */
	protected static function validatePassword($password) {
		if (empty($password)) {
			throw new InvalidPasswordException();
		}

		$password = \trim($password);

		if (\strlen($password) < 1) {
			throw new InvalidPasswordException();
		}

		return $password;
	}

	/**
	 * Создает запрос на подтверждение по электронной почте
	 *
	 * Функция обратного вызова должна иметь следующую подпись:
	 *
	 * `function ($selector, $token)`
	 *
	 * Обе части информации должны быть отправлены пользователю, как правило, встроены в ссылку.
	 *
	 * Когда пользователь хочет подтвердить свой адрес электронной почты в качестве следующего шага, снова потребуются обе части.
	 *
	 * @param int $userId ID пользователя
	 * @param string $email адрес электронной почты для подтверждения
	 * @param callable $callback функция, которая отправляет пользователю электронное письмо с подтверждением
	 * @throws AuthError если возникла внутренняя проблем
	 */
	protected function createConfirmationRequest($userId, $email, callable $callback) {
		$selector = self::createRandomString(16);
		$token = self::createRandomString(16);
		$tokenHashed = \password_hash($token, \PASSWORD_DEFAULT);
		$expires = \time() + 60 * 60 * 24;

		try {
			$this->db->insert(
				$this->makeTableNameComponents('users_confirmations'),
				[
					'user_id' => (int) $userId,
					'email' => $email,
					'selector' => $selector,
					'token' => $tokenHashed,
					'expires' => $expires
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
	 * Удаляет существующую директиву, по которой пользователь остается в системе («запомни меня»).
	 *
	 * @param int $userId ID пользователя, который больше не должен находиться в системе
	 * @param string $selector (необязательно) селектор, удаление которого должно быть ограничено
	 * @throws AuthError если возникла внутренняя проблема
	 */
	protected function deleteRememberDirectiveForUserById($userId, $selector = null) {
		$whereMappings = [];

		if (isset($selector)) {
			$whereMappings['selector'] = (string) $selector;
		}

		$whereMappings['user'] = (int) $userId;

		try {
			$this->db->delete(
				$this->makeTableNameComponents('users_remembered'),
				$whereMappings
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}
	}

	/**
	 * Запускает принудительный выход из системы во всех сеансах, принадлежащих указанному пользователю.
	 *
	 * @param int $userId ID пользователя для выхода
	 * @throws AuthError если возникла внутренняя проблема
	 */
	protected function forceLogoutForUserById($userId) {
		$this->deleteRememberDirectiveForUserById($userId);
		$this->db->exec(
			'UPDATE ' . $this->makeTableName('users') . ' SET force_logout = force_logout + 1 WHERE id = ?',
			[ $userId ]
		);
	}

	/**
	 * Создает (квалифицированное) полное имя таблицы из необязательного квалификатора, необязательного префикса и самого имени таблицы
	 *
	 * Необязательный квалификатор может быть именем базы данных или именем схемы, например
	 *
	 * @param string $name название таблицы
	 * @return string[] компоненты (квалифицированного) полного имени таблицы
	 */
	protected function makeTableNameComponents($name) {
		$components = [];

		if (!empty($this->dbSchema)) {
			$components[] = $this->dbSchema;
		}

		if (!empty($name)) {
			if (!empty($this->dbTablePrefix)) {
				$components[] = $this->dbTablePrefix . $name;
			}
			else {
				$components[] = $name;
			}
		}

		return $components;
	}

	/**
	 * Создает (квалифицированное) полное имя таблицы из необязательного квалификатора, необязательного префикса и самого имени таблицы
	 *
	 * Необязательный квалификатор может быть именем базы данных или именем схемы, например
	 *
	 * @param string $name название таблицы
	 * @return string (квалифицированное) полное имя таблицы
	 */
	protected function makeTableName($name) {
		$components = $this->makeTableNameComponents($name);

		return \implode('.', $components);
	}

}
