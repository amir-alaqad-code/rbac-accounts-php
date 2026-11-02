<?php
declare(strict_types=1);


$rolePermissions = [];
$userRoles = [];
$accounts = ['AC-101' => 'Everyday account'];

function grantPermissionToRole(array &$rolePermissions, string $role, string $permission): void
{
    $allowedPermissions = ['create', 'view', 'update', 'delete'];
    if (!in_array($permission, $allowedPermissions, true)) {
        throw new InvalidArgumentException('Unknown permission: ' . $permission);
    }

    $rolePermissions[$role] ??= [];
    if (!in_array($permission, $rolePermissions[$role], true)) {
        $rolePermissions[$role][] = $permission;
    }
}

function assignRoleToUser(array &$userRoles, array $rolePermissions, string $user, string $role): void
{
    if (!array_key_exists($role, $rolePermissions)) {
        throw new InvalidArgumentException('Unknown role: ' . $role);
    }

    $userRoles[$user] ??= [];
    if (!in_array($role, $userRoles[$user], true)) {
        $userRoles[$user][] = $role;
    }
}

function canAccess(array $userRoles, array $rolePermissions, string $user, string $permission): bool
{
    foreach ($userRoles[$user] ?? [] as $role) {
        if (in_array($permission, $rolePermissions[$role] ?? [], true)) {
            return true;
        }
    }
    return false;
}

function performAccountAction(
    array &$accounts,
    array $userRoles,
    array $rolePermissions,
    string $user,
    string $action,
    string $accountId,
    string $accountName = ''
): void {
    $label = ucfirst($user) . ' tries to ' . $action . ' ' . $accountId . ' -> ';

    if (!canAccess($userRoles, $rolePermissions, $user, $action)) {
        echo $label . 'DENIED (this role does not allow it)' . PHP_EOL;
        return;
    }

    if ($action === 'create') {
        if (isset($accounts[$accountId])) {
            echo $label . 'FAILED (account already exists)' . PHP_EOL;
            return;
        }
        $accounts[$accountId] = $accountName;
        echo $label . 'ALLOWED (created: ' . $accountName . ')' . PHP_EOL;
        return;
    }

    if (!isset($accounts[$accountId])) {
        echo $label . 'FAILED (account not found)' . PHP_EOL;
        return;
    }

    if ($action === 'view') {
        echo $label . 'ALLOWED (account name: ' . $accounts[$accountId] . ')' . PHP_EOL;
    } elseif ($action === 'update') {
        $accounts[$accountId] = $accountName;
        echo $label . 'ALLOWED (new name: ' . $accountName . ')' . PHP_EOL;
    } elseif ($action === 'delete') {
        unset($accounts[$accountId]);
        echo $label . 'ALLOWED (deleted)' . PHP_EOL;
    }
}

// Give each role the permissions required in the assignment.
foreach (['create', 'view', 'update', 'delete'] as $permission) {
    grantPermissionToRole($rolePermissions, 'Admin', $permission);
}
foreach (['view', 'update'] as $permission) {
    grantPermissionToRole($rolePermissions, 'Manager', $permission);
}
grantPermissionToRole($rolePermissions, 'Customer', 'view');

// Sample users for the demonstration.
assignRoleToUser($userRoles, $rolePermissions, 'amir', 'Admin');
assignRoleToUser($userRoles, $rolePermissions, 'samer', 'Manager');
assignRoleToUser($userRoles, $rolePermissions, 'dina', 'Customer');

echo 'PERMISSIONS BY ROLE' . PHP_EOL;
foreach ($rolePermissions as $role => $permissions) {
    echo $role . ': ' . implode(', ', $permissions) . PHP_EOL;
}

echo PHP_EOL . 'USERS AND THEIR ROLES' . PHP_EOL;
foreach ($userRoles as $user => $roles) {
    echo $user . ': ' . implode(', ', $roles) . PHP_EOL;
}

echo PHP_EOL . 'ACCOUNT REQUESTS' . PHP_EOL;
performAccountAction($accounts, $userRoles, $rolePermissions, 'amir', 'create', 'AC-205', 'Trip savings');
performAccountAction($accounts, $userRoles, $rolePermissions, 'amir', 'view', 'AC-205');
performAccountAction($accounts, $userRoles, $rolePermissions, 'amir', 'update', 'AC-205', 'Travel savings');
performAccountAction($accounts, $userRoles, $rolePermissions, 'amir', 'delete', 'AC-205');
performAccountAction($accounts, $userRoles, $rolePermissions, 'samer', 'view', 'AC-101');
performAccountAction($accounts, $userRoles, $rolePermissions, 'samer', 'update', 'AC-101', 'Everyday account - reviewed');
performAccountAction($accounts, $userRoles, $rolePermissions, 'samer', 'create', 'AC-301', 'Unapproved account');
performAccountAction($accounts, $userRoles, $rolePermissions, 'samer', 'delete', 'AC-101');
performAccountAction($accounts, $userRoles, $rolePermissions, 'dina', 'view', 'AC-101');
performAccountAction($accounts, $userRoles, $rolePermissions, 'dina', 'create', 'AC-401', 'Unapproved account');
performAccountAction($accounts, $userRoles, $rolePermissions, 'dina', 'update', 'AC-101', 'Unapproved change');
performAccountAction($accounts, $userRoles, $rolePermissions, 'dina', 'delete', 'AC-101');

echo PHP_EOL . 'ACCOUNTS AT THE END' . PHP_EOL;
foreach ($accounts as $accountId => $accountName) {
    echo $accountId . ': ' . $accountName . PHP_EOL;
}
