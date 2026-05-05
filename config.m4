dnl config.m4 for security_guard extension

PHP_ARG_ENABLE([security-guard],
  [whether to enable security_guard support],
  [AS_HELP_STRING([--enable-security-guard],
    [Enable security_guard extension])],
  [no])

if test "$PHP_SECURITY_GUARD" != "no"; then
  AC_DEFINE(HAVE_SECURITY_GUARD, 1, [Whether you have security_guard])

  security_guard_sources="security_guard.c \
    src/config_loader.c \
    src/policy_engine.c \
    src/command_policy.c \
    src/file_policy.c \
    src/network_policy.c \
    src/logger.c \
    src/php_hooks.c \
    src/utils.c"

  PHP_NEW_EXTENSION(security_guard, $security_guard_sources, $ext_shared,, -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1)
  PHP_ADD_INCLUDE([$ext_srcdir/include])
fi
