"""Единый разбор прав и признака администратора для всех сервисов.

Шлюз отдаёт роли как есть: право, выданное роли как 'finder.*', приходит в
X-User-Service-Permissions именно строкой со звёздочкой, без разворачивания в
список. Сервисы сравнивали права точным `in` и такое право не видели — пункт
меню пропадал, а роут отвечал 403 при формально выданном доступе.

Здесь одна реализация на весь флот. Дублировать её в каждом сервисе не нужно:
finder, referal и client_service импортируют отсюда.
"""

from typing import Any, Dict, Iterable, List, Sequence, Tuple, Union


def permission_granted(permission_name: str, permissions: Iterable[str]) -> bool:
    """Есть ли право в списке, с учётом шаблонов.

    Поддерживает точное совпадение, голую '*' и префиксные шаблоны вида
    'finder.*', покрывающие 'finder.projects_info_update'.
    """
    if not permission_name:
        return False

    for perm in permissions or ():
        if perm == permission_name or perm == '*':
            return True
        # 'finder.*' -> префикс 'finder.'
        if perm.endswith('.*') and permission_name.startswith(perm[:-1]):
            return True
    return False


def any_permission_granted(permission_names: Sequence[str], permissions: Iterable[str]) -> bool:
    """Хватает любого права из списка. Права разворачиваем один раз."""
    permissions = list(permissions or ())
    return any(permission_granted(name, permissions) for name in permission_names)


def extract_permissions(user: Union[Dict[str, Any], Any, None]) -> List[str]:
    """Список прав из пользователя любой формы.

    AuthMiddleware кладёт в g.user объект UserContext, а to_dict() и служебные
    вызовы — словарь. Раньше каждая проверка разбирала обе формы по-своему, и
    расхождения давали разный ответ в шаблоне и на роуте.
    """
    if user is None:
        return []
    if isinstance(user, dict):
        return list(user.get('permissions') or ())
    return list(getattr(user, 'permissions', None) or ())