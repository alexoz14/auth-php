<?php

namespace Delight\Auth;

use Delight\Db\PdoDatabase;
use Delight\Db\PdoDsn;
use Delight\Db\Throwable\Error;

/** Компонент, который может использоваться для административных задач привилегированными и авторизованными пользователями */
final class Administration extends UserManager {

	/**
	 * @param PdoDatabase|PdoDsn|\PDO $databaseConnection соединение с базой данных
	 * @param string|null $dbTablePrefix (необязательно) префикс для имен всех таблиц базы данных, используемых этим компонентом
	 * @param string|null $dbSchema (необязательно) имя схемы для всех таблиц базы данных, используемых этим компонентом
	 */
	public function __construct($databaseConnection, $dbTablePrefix = null, $dbSchema = null) {
		parent::__construct($databaseConnection, $dbTablePrefix, $dbSchema);
	}

	/**
	 * Создает нового пользователя
	 *
	 * @param string $email адрес электронной почты для регистрации
	 * @param string $password пароль для новой учетной записи
	 * @param string|null $username (необязательно) имя пользователя, которое будет отображаться
	 * @return int ID созданного пользователя
	 * @throws InvalidEmailException если адрес электронной почты недействителен
	 * @throws InvalidPasswordException если пароль был недействителен
	 * @throws UserAlreadyExistsException если пользователь с указанным адресом электронной почты уже существует
	 * @throws AuthError если возникла внутренняя проблема
     */
	public function createUser($email, $password, $username = null) {
		return $this->createUserInternal(false, $email, $password, $username, null);
	}

	public function createUserWithUniqueUsername($email, $password, $username = null) {
		return $this->createUserInternal(true, $email, $password, $username, null);
	}

	/**
	 * Удаляет пользователя с указанным ID
	 *
	 * Это действие не может быть отменено
	 *
	 * @param int $id id пользвателя
	 * @throws UnknownIdException если не найдено ни одного пользователя с указанным ID
	 * @throws AuthError если возникла внутренняя проблема
	 */
	public function deleteUserById($id) {
		$numberOfDeletedUsers = $this->deleteUsersByColumnValue('id', (int) $id);

		if ($numberOfDeletedUsers === 0) {
			throw new UnknownIdException();
		}
	}

	/**
	 * Удаляет пользователя с указанным адресом электронной почты
	 *
     * Это действие не может быть отменено
     *
	 * @param string $email адрес электронной почты пользователя, которого нужно удалить
	 * @throws InvalidEmailException если не найдено ни одного пользователя с указанным адресом электронной почты
	 * @throws AuthError если возникла внутренняя проблема
	 */
	public function deleteUserByEmail($email) {
		$email = self::validateEmailAddress($email);

		$numberOfDeletedUsers = $this->deleteUsersByColumnValue('email', $email);

		if ($numberOfDeletedUsers === 0) {
			throw new InvalidEmailException();
		}
	}

	/**
	 * Удаляет пользователя с указанным именем пользователя
	 *
	 * Это действие не может быть отменено
	 *
	 * @param string $username имя пользователя, которого нужно удалить
	 * @throws UnknownUsernameException если ни один пользователь с указанным именем не найден
	 * @throws AmbiguousUsernameException если найдено несколько пользователей с указанным именем
	 * @throws AuthError если возникла внутренняя проблема
	 */
	public function deleteUserByUsername($username) {
		$userData = $this->getUserDataByUsername(
			\trim($username),
			[ 'id' ]
		);

		$this->deleteUsersByColumnValue('id', (int) $userData['id']);
	}

	/**
	 * Назначает указанную роль пользователю с данным ID
	 *
	 * У пользователя может быть любое количество ролей (т.е. Вообще без роли, одна роль или любая комбинация ролей).
	 *
	 * @param int $userId ID пользователя, которому назначена роль
	 * @param int $role роль как одна из констант класса {@see Role}
	 * @throws UnknownIdException если не найдено ни одного пользователя с указанным ID
	 *
	 * @see Role
	 */
	public function addRoleForUserById($userId, $role) {
		$userFound = $this->addRoleForUserByColumnValue(
			'id',
			(int) $userId,
			$role
		);

		if ($userFound === false) {
			throw new UnknownIdException();
		}
	}

	/**
	 * Назначает указанную роль пользователю с указанным адресом электронной почты
	 *
	 * У пользователя может быть любое количество ролей (т.е. Вообще без роли, одна роль или любая комбинация ролей).
     *
	 * @param string $userEmail адрес электронной почты пользователя, которому назначена роль
	 * @param int $role роль как одна из констант класса {@see Role}
	 * @throws InvalidEmailException если не найдено ни одного пользователя с указанным адресом электронной почты
	 *
	 * @see Role
	 */
	public function addRoleForUserByEmail($userEmail, $role) {
		$userEmail = self::validateEmailAddress($userEmail);

		$userFound = $this->addRoleForUserByColumnValue(
			'email',
			$userEmail,
			$role
		);

		if ($userFound === false) {
			throw new InvalidEmailException();
		}
	}

	/**
	 * Назначает указанную роль пользователю с данным именем пользователя
	 *
	 * У пользователя может быть любое количество ролей (т. Е. Вообще без роли, одна роль или любая комбинация ролей).
	 *
	 * @param string $username имя пользователя, которому назначена роль
	 * @param int $role роль как одна из констант класса {@see Role}
	 * @throws UnknownUsernameException если ни один пользователь с указанным именем не найден
	 * @throws AmbiguousUsernameException если найдено несколько пользователей с указанным именем
	 *
	 * @see Role
	 */
	public function addRoleForUserByUsername($username, $role) {
		$userData = $this->getUserDataByUsername(
			\trim($username),
			[ 'id' ]
		);

		$this->addRoleForUserByColumnValue(
			'id',
			(int) $userData['id'],
			$role
		);
	}

	/**
	 * Забирает указанную роль у пользователя с данным ID
	 *
	 * У пользователя может быть любое количество ролей (т.е. Вообще без роли, одна роль или любая комбинация ролей).
     *
	 * @param int $userId ID пользователя, которому нужно отобрать роль
	 * @param int $role роль как одна из констант класса {@see Role}
	 * @throws UnknownIdException если не найдено ни одного пользователя с указанным ID
	 *
	 * @see Role
	 */
	public function removeRoleForUserById($userId, $role) {
		$userFound = $this->removeRoleForUserByColumnValue(
			'id',
			(int) $userId,
			$role
		);

		if ($userFound === false) {
			throw new UnknownIdException();
		}
	}

	/**
	 * Забирает указанную роль у пользователя с данным адресом электронной почты
	 *
	 * У пользователя может быть любое количество ролей (т.е. Вообще без роли, одна роль или любая комбинация ролей).
     *
	 * @param string $userEmail адрес электронной почты пользователя, от которого требуется отменить роль
	 * @param int $role роль как одна из констант класса {@see Role}
	 * @throws InvalidEmailException если не найдено ни одного пользователя с указанным адресом электронной почты
	 *
	 * @see Role
	 */
	public function removeRoleForUserByEmail($userEmail, $role) {
		$userEmail = self::validateEmailAddress($userEmail);

		$userFound = $this->removeRoleForUserByColumnValue(
			'email',
			$userEmail,
			$role
		);

		if ($userFound === false) {
			throw new InvalidEmailException();
		}
	}

	/**
	 * Забирает указанную роль у пользователя с данным именем пользователя
	 *
	 * У пользователя может быть любое количество ролей (т.е. Вообще без роли, одна роль или любая комбинация ролей).
	 *
	 * @param string $username имя пользователя, от которого требуется отнять роль
	 * @param int $role роль как одна из констант класса {@see Role}
	 * @throws UnknownUsernameException если ни один пользователь с указанным именем не найден
	 * @throws AmbiguousUsernameException если найдено несколько пользователей с указанным именем
	 *
	 * @see Role
	 */
	public function removeRoleForUserByUsername($username, $role) {
		$userData = $this->getUserDataByUsername(
			\trim($username),
			[ 'id' ]
		);

		$this->removeRoleForUserByColumnValue(
			'id',
			(int) $userData['id'],
			$role
		);
	}

	/**
	 * Возвращает, имеет ли пользователь с данным ID указанную роль.
	 *
	 * @param int $userId ID пользователя, для которого нужно проверить роли
	 * @param int $role роль как одна из констант класса {@see Role}
	 * @return bool
	 * @throws UnknownIdException если не найдено ни одного пользователя с указанным ID
	 *
	 * @see Role
	 */
	public function doesUserHaveRole($userId, $role) {
		if (empty($role) || !\is_numeric($role)) {
			return false;
		}

		$userId = (int) $userId;

		$rolesBitmask = $this->db->selectValue(
			'SELECT roles_mask FROM ' . $this->makeTableName('users') . ' WHERE id = ?',
			[ $userId ]
		);

		if ($rolesBitmask === null) {
			throw new UnknownIdException();
		}

		$role = (int) $role;

		return ($rolesBitmask & $role) === $role;
	}

	/**
	 * Возвращает роли пользователя с данным идентификатором, сопоставляя числовые значения с их описательными именами.
     *
	 * @param int $userId ID пользователя, для которого нужно вернуть роли
	 * @return array
	 * @throws UnknownIdException если не найдено ни одного пользователя с указанным ID
	 *
	 * @see Role
	 */
	public function getRolesForUserById($userId) {
		$userId = (int) $userId;

		$rolesBitmask = $this->db->selectValue(
			'SELECT roles_mask FROM ' . $this->makeTableName('users') . ' WHERE id = ?',
			[ $userId ]
		);

		if ($rolesBitmask === null) {
			throw new UnknownIdException();
		}

		return \array_filter(
			Role::getMap(),
			function ($each) use ($rolesBitmask) {
				return ($rolesBitmask & $each) === $each;
			},
			\ARRAY_FILTER_USE_KEY
		);
	}

	/**
	 *Входит в систему как пользователь с указанным ID
	 *
	 * @param int $id идентификатор пользователя для входа в систему как
	 * @throws UnknownIdException если не найдено ни одного пользователя с указанным ID
	 * @throws EmailNotVerifiedException если пользователь еще не подтвердил свой адрес электронной почты с помощью метода подтверждения
     * @throws AuthError если возникла внутренняя проблема
	 */
	public function logInAsUserById($id) {
		$numberOfMatchedUsers = $this->logInAsUserByColumnValue('id', (int) $id);

		if ($numberOfMatchedUsers === 0) {
			throw new UnknownIdException();
		}
	}

	/**
	 * Входит в систему как пользователь с указанным адресом электронной почты
	 *
	 * @param string $email адрес электронной почты пользователя для входа в систему как
	 * @throws InvalidEmailException если не найдено ни одного пользователя с указанным адресом электронной почты
	 * @throws EmailNotVerifiedException если пользователь еще не подтвердил свой адрес электронной почты с помощью метода подтверждения
	 * @throws AuthError если возникла внутренняя проблема
     */
	public function logInAsUserByEmail($email) {
		$email = self::validateEmailAddress($email);

		$numberOfMatchedUsers = $this->logInAsUserByColumnValue('email', $email);

		if ($numberOfMatchedUsers === 0) {
			throw new InvalidEmailException();
		}
	}

	/**
	 * Выполняет вход как пользователь с указанным отображаемым именем
	 *
	 * @param string $username отображаемое имя пользователя для входа в систему как
	 * @throws UnknownUsernameException если ни один пользователь с указанным именем не найден
	 * @throws AmbiguousUsernameException если найдено несколько пользователей с указанным именем
	 * @throws EmailNotVerifiedException если пользователь еще не подтвердил свой адрес электронной почты с помощью метода подтверждения
	 * @throws AuthError если возникла внутренняя проблема
     */
	public function logInAsUserByUsername($username) {
		$numberOfMatchedUsers = $this->logInAsUserByColumnValue('username', \trim($username));

		if ($numberOfMatchedUsers === 0) {
			throw new UnknownUsernameException();
		}
		elseif ($numberOfMatchedUsers > 1) {
			throw new AmbiguousUsernameException();
		}
	}

	/**
	 * Изменяет пароль для пользователя с данным ID
	 *
	 * @param int $userId ID пользователя, пароль которого нужно изменить
	 * @param string $newPassword новый пароль для установки
	 * @throws UnknownIdException если не найдено ни одного пользователя с указанным ID
	 * @throws InvalidPasswordException если желаемый новый пароль недействителен
	 * @throws AuthError если возникла внутренняя проблема
	 */
	public function changePasswordForUserById($userId, $newPassword) {
		$userId = (int) $userId;
		$newPassword = self::validatePassword($newPassword);

		$this->updatePasswordInternal(
			$userId,
			$newPassword
		);

		$this->forceLogoutForUserById($userId);
	}

	/**
	 * Изменяет пароль для пользователя с данным именем пользователя
	 *
	 * @param string $username имя пользователя, пароль которого нужно изменить
	 * @param string $newPassword новый пароль для установки
	 * @throws UnknownUsernameException если ни один пользователь с указанным именем не найден
	 * @throws AmbiguousUsernameException если найдено несколько пользователей с указанным именем
	 * @throws InvalidPasswordException если желаемый новый пароль недействителен
	 * @throws AuthError если возникла внутренняя проблема
	 */
	public function changePasswordForUserByUsername($username, $newPassword) {
		$userData = $this->getUserDataByUsername(
			\trim($username),
			[ 'id' ]
		);

		$this->changePasswordForUserById(
			(int) $userData['id'],
			$newPassword
		);
	}

	/**
	 * Удаляет всех существующих пользователей, у которых столбец с указанным именем имеет заданное значение
	 *
	 * Вы никогда не должны передавать не надежные параметры, которые принимают имя столбца.
	 *
	 * @param string $columnName имя столбца для фильтрации по
	 * @param mixed $columnValue значение, которое нужно искать в выбранном столбце
	 * @return int количество удаленных пользователей
	 * @throws AuthError если возникла внутренняя проблема
	 */
	private function deleteUsersByColumnValue($columnName, $columnValue) {
		try {
			return $this->db->delete(
				$this->makeTableNameComponents('users'),
				[
					$columnName => $columnValue
				]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}
	}

	/**
	 * Изменяет роли для пользователя, в котором столбец с указанным именем имеет заданное значение.
	 *
	 * Вы никогда не должны передавать не надежные параметры, которые принимают имя столбца.
	 *
	 * @param string $columnName имя столбца для фильтрации по
	 * @param mixed $columnValue значение, которое нужно искать в выбранном столбце
	 * @param callable $modification модификация для применения к существующей битовой маске ролей
	 * @return bool был ли найден какой-либо пользователь с заданными ограничениями столбца
	 * @throws AuthError если возникла внутренняя проблема
	 *
	 * @see Role
	 */
	private function modifyRolesForUserByColumnValue($columnName, $columnValue, callable $modification) {
		try {
			$userData = $this->db->selectRow(
				'SELECT id, roles_mask FROM ' . $this->makeTableName('users') . ' WHERE ' . $columnName . ' = ?',
				[ $columnValue ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		if ($userData === null) {
			return false;
		}

		$newRolesBitmask = $modification($userData['roles_mask']);

		try {
			$this->db->exec(
				'UPDATE ' . $this->makeTableName('users') . ' SET roles_mask = ? WHERE id = ?',
				[
					$newRolesBitmask,
					(int) $userData['id']
				]
			);

			return true;
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}
	}

	/**
	 * Назначает указанную роль пользователю, где столбец с указанным именем имеет заданное значение
	 *
	 * Вы никогда не должны передавать не надежные параметры, которые принимают имя столбца.
	 *
	 * @param string $columnName имя столбца для фильтрации по
	 * @param mixed $columnValue значение, которое нужно искать в выбранном столбце
	 * @param int $role роль как одна из констант класса {@see Role}
	 * @return bool был ли найден какой-либо пользователь с заданными ограничениями столбца
	 *
	 * @see Role
	 */
	private function addRoleForUserByColumnValue($columnName, $columnValue, $role) {
		$role = (int) $role;

		return $this->modifyRolesForUserByColumnValue(
			$columnName,
			$columnValue,
			function ($oldRolesBitmask) use ($role) {
				return $oldRolesBitmask | $role;
			}
		);
	}

	/**
	 * Отнимает указанную роль у пользователя, где столбец с указанным именем имеет заданное значение
	 *
	 * Вы никогда не должны передавать не надежные параметры, которые принимают имя столбца.
	 *
	 * @param string $columnName имя столбца для фильтрации по
	 * @param mixed $columnValue значение, которое нужно искать в выбранном столбце
	 * @param int $role роль как одна из констант класса {@see Role}
	 * @return bool был ли найден какой-либо пользователь с заданными ограничениями столбца
	 *
	 * @see Role
	 */
	private function removeRoleForUserByColumnValue($columnName, $columnValue, $role) {
		$role = (int) $role;

		return $this->modifyRolesForUserByColumnValue(
			$columnName,
			$columnValue,
			function ($oldRolesBitmask) use ($role) {
				return $oldRolesBitmask & ~$role;
			}
		);
	}

	/**
	 * Выполняет вход как пользователь, для которого столбец с указанным именем имеет заданное значение
	 *
	 * Вы никогда не должны передавать не надежные параметры, которые принимают имя столбца.
	 *
	 * @param string $columnName имя столбца для фильтрации по
	 * @param mixed $columnValue значение, которое нужно искать в выбранном столбце
	 * @return int количество совпавших пользователей (где только значение один означает, что вход в систему мог быть успешным)
	 * @throws EmailNotVerifiedException если пользователь еще не подтвердил свой адрес электронной почты с помощью метода подтверждения
	 * @throws AuthError если возникла внутренняя проблема
	 */
	private function logInAsUserByColumnValue($columnName, $columnValue) {
		try {
			$users = $this->db->select(
				'SELECT verified, id, email, username, status, roles_mask FROM ' . $this->makeTableName('users') . ' WHERE ' . $columnName . ' = ? LIMIT 2 OFFSET 0',
				[ $columnValue ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		$numberOfMatchingUsers = ($users !== null) ? \count($users) : 0;

		if ($numberOfMatchingUsers === 1) {
			$user = $users[0];

			if ((int) $user['verified'] === 1) {
				$this->onLoginSuccessful($user['id'], $user['email'], $user['username'], $user['status'], $user['roles_mask'], \PHP_INT_MAX, false);
			}
			else {
				throw new EmailNotVerifiedException();
			}
		}

		return $numberOfMatchingUsers;
	}

}
