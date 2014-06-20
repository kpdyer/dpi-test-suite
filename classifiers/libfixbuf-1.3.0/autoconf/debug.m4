# AC_DEBUG()
#
# Check for commandline options requesting DEBUG feature.
# Might define DEBUG, NODEBUG, or NDEBUG, depending on flags given.
AC_DEFUN([AC_DEBUG],[dnl
  AC_ARG_ENABLE([debug], 
    AC_HELP_STRING([--enable-debug], [include debugging code (default=no)]),
    [ case "${enableval}" in
      yes) debug=true ;;
      no) debug=false ;;
      *) AC_MSG_ERROR(bad value ${enableval} for debug option) ;;
    esac],
    [debug=false])
  if test "$debug" = true; then
    AC_SUBST([DEBUG_CFLAGS],["-DDEBUG -ggdb -O0"])
  else
    AC_SUBST([DEBUG_CFLAGS],["-DNDEBUG"])
  fi
])

