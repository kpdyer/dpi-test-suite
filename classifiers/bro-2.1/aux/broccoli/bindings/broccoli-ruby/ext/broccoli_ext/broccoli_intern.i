%module "broccoli_ext"
#pragma SWIG nowarn=801,451

%include cpointer.i
%include typemaps.i

%{
/* Includes the header in the wrapper code */
#include "broccoli.h"

#include <inttypes.h>
typedef int64_t int64;
%}

%{

/* Convert Ruby String to BroString */
BroString to_brostring(VALUE obj){
  Check_Type(obj, T_STRING);
  BroString bs;
  bro_string_set(&bs, STR2CSTR(obj));
  return bs;
}

static void
wrap_BroCompactEventFunc(BroConn *bc, void *user_data, BroEvMeta *meta)
{
  int i;
  int callback_arity = 0;
  VALUE proc = (VALUE)user_data;
  VALUE out[15] = {Qnil,Qnil,Qnil,Qnil,Qnil,Qnil,Qnil,Qnil,
                   Qnil,Qnil,Qnil,Qnil,Qnil,Qnil,Qnil};
  callback_arity = NUM2INT(rb_funcall(proc, rb_intern("arity"), 0));
  // The absence of any arguments is the same as 0 arguments
  if ( callback_arity == -1 )
    ++callback_arity;
  if ( callback_arity != meta->ev_numargs )
  {
    printf("ERROR: callback has %d arguments when it should have %d arguments.\n",
           callback_arity,
           meta->ev_numargs);
  }
  for (i=0 ; i < meta->ev_numargs ; i++)
  {
    //printf("Loop #%i\n", i);
    switch (meta->ev_args[i].arg_type)
    {
      case BRO_TYPE_RECORD:
        //printf("Found a BroRecord in the callback wrapper\n");
        out[i] = SWIG_NewPointerObj(SWIG_as_voidptr(meta->ev_args[i].arg_data), SWIGTYPE_p_bro_record, 0 |  0 );
        break;
      case BRO_TYPE_PORT:
        out[i] = SWIG_NewPointerObj(SWIG_as_voidptr(meta->ev_args[i].arg_data), SWIGTYPE_p_bro_port, 0 |  0 );
        break;
      case BRO_TYPE_INT:
      case BRO_TYPE_ENUM:
        //printf("Found an enum/integer in the callback wrapper\n");
        out[i] = INT2NUM( *((int *) meta->ev_args[i].arg_data) );
        break;
      case BRO_TYPE_BOOL:
        //printf("Found a boolean in the callback wrapper\n");
        out[i] = *((int *) meta->ev_args[i].arg_data) ? Qtrue : Qfalse;
        break;
      case BRO_TYPE_STRING:
      case BRO_TYPE_FILE:
        //printf("Found a BroString in the callback wrapper\n");
        out[i] = rb_str_new( (char*) bro_string_get_data( (BroString*) meta->ev_args[i].arg_data ),
                                     bro_string_get_length( (BroString*) meta->ev_args[i].arg_data ) );
        break;
      case BRO_TYPE_TIME:
      case BRO_TYPE_DOUBLE:
      case BRO_TYPE_INTERVAL:
        //printf("Found a double in the callback wrapper\n");
        out[i] = rb_float_new( *((double *) meta->ev_args[i].arg_data) );
        break;
      case BRO_TYPE_COUNT:
        //printf("Found a 32bit unsigned integer in the callback wrapper\n");
        out[i] = UINT2NUM( *((uint32 *) meta->ev_args[i].arg_data) );
        break;
      case BRO_TYPE_IPADDR:
        {
        //printf("Found an ip address... making it a string\n");
        //output ip addresses as strings that can be unpacked from ruby.
        BroAddr* a = (BroAddr*) meta->ev_args[i].arg_data;
        if ( bro_util_is_v4_addr(a) )
            out[i] = rb_str_new((char *) (&a->addr[3]), sizeof(uint32));
        else
            out[i] = rb_str_new((char *) a->addr, 4 * sizeof(uint32));
        break;
        }
      case BRO_TYPE_COUNTER:
      case BRO_TYPE_TIMER:
      case BRO_TYPE_PATTERN:
      case BRO_TYPE_SUBNET:
      case BRO_TYPE_ANY:
      case BRO_TYPE_TABLE:
      case BRO_TYPE_UNION:
      case BRO_TYPE_LIST:
      case BRO_TYPE_FUNC:
      case BRO_TYPE_VECTOR:
      case BRO_TYPE_ERROR:
      case BRO_TYPE_MAX:
        printf("Type not yet handled.\n");
        break;
      default:
        printf("Invalid type was registered for callback!\n");
        break;
    }
  }

  // Call the ruby proc object
  rb_funcall2(proc, rb_intern("call"), callback_arity, out);

  bc = NULL;
  user_data = NULL;
}

%}

%typemap(in) (BroCompactEventFunc func, void *user_data)
{
  $1 = (BroCompactEventFunc) wrap_BroCompactEventFunc;
  $2 = (void *)$input;
}

// Clean up bro strings after they're used
%typemap(ret) int bro_record_add_val,
              int bro_record_set_named_val,
              int bro_record_set_nth_val
{
  if(arg3 == BRO_TYPE_STRING) { bro_string_cleanup(arg5); }
}
%typemap(ret) int bro_event_add_val
{
  if(arg2 == BRO_TYPE_STRING) { bro_string_cleanup(arg4); }
}

//bro_record_add_val
//bro_record_set_named_val
//bro_record_set_nth_val
//bro_event_add_val
//bro_event_set_val
%typemap(in) (int type, const char *type_name, const void *val)
{
  int64 tmp_int64;
  uint64 tmp_uint64;
  int tmp_int;
  double tmp_double;
  BroString tmp_brostring;
  void *tmp_swigpointer;
  int res;
  int type;
  VALUE value;
  VALUE type_name;

  // Use ruby's array accessor method to get the type, type_name and value
  type = NUM2INT(rb_funcall($input, rb_intern("at"), 1, INT2NUM(0)));
  $1 = type;
  type_name = rb_funcall($input, rb_intern("at"), 1, INT2NUM(1));
  if ( rb_funcall(type_name, rb_intern("=="), 1, Qnil) == Qtrue )
  {
    $2 = NULL;
  } else {
    Check_Type(type_name, T_STRING);
    $2 = (char *)STR2CSTR(type_name);
  }
  value = rb_funcall($input, rb_intern("at"), 1, INT2NUM(2));

  switch(type)
  {
    case BRO_TYPE_INT:
      //printf("Matched on Fixnum!  Storing value as an int (%i)\n", NUM2LL(value));
      tmp_int64 = NUM2LL(value);
      $3 = &tmp_int64;
      break;

    case BRO_TYPE_BOOL:
      //printf("Matched on boolean!  Storing value as an integer\n");
      tmp_int = value ? 1 : 0;
      $3 = &tmp_int;
      break;

    case BRO_TYPE_TIME:
    case BRO_TYPE_DOUBLE:
    case BRO_TYPE_INTERVAL:
      //printf("Storing value as a double (%f)\n", rb_num2dbl($input));
      tmp_double = rb_num2dbl(value);
      $3 = &tmp_double;
      break;

    case BRO_TYPE_COUNT:
    case BRO_TYPE_ENUM:
      //printf("Storing value as a uint64\n");
      tmp_uint64 = NUM2ULL(value);
      $3 = &tmp_uint64;
      break;

    case BRO_TYPE_IPADDR:
      //printf("Storing value as a BroAddr\n");
      res = SWIG_ConvertPtr(value, &tmp_swigpointer, SWIGTYPE_p_bro_addr, 0);
      if (!SWIG_IsOK(res)) {
        SWIG_exception_fail(SWIG_ArgError(res), "the value for $symname was supposed to be a BroAddr");
      }
      $3 = (BroAddr *)(tmp_swigpointer);
      break;

    case BRO_TYPE_STRING:
      //printf("Storing value as a BroString\n");
      tmp_brostring = to_brostring(value);
      $3 = &tmp_brostring;
      break;

    case BRO_TYPE_PORT:
      //printf("Storing value as a BroPort\n");
      res = SWIG_ConvertPtr(value, &tmp_swigpointer, SWIGTYPE_p_bro_port, 0);
      if (!SWIG_IsOK(res)) {
        SWIG_exception_fail(SWIG_ArgError(res), "the value for $symname was supposed to be a BroPort");
      }
      $3 = (BroPort *)(tmp_swigpointer);
      break;

    case BRO_TYPE_SUBNET:
      //printf("Storing value as a BroSubnet\n");
      res = SWIG_ConvertPtr(value, &tmp_swigpointer, SWIGTYPE_p_bro_subnet, 0);
      if (!SWIG_IsOK(res)) {
        SWIG_exception_fail(SWIG_ArgError(res), "the value for $symname was supposed to be a BroSubnet");
      }
      $3 = (BroSubnet *)(tmp_swigpointer);
      break;

    case BRO_TYPE_RECORD:
      //printf("Storing value as a BroRecord\n");
      res = SWIG_ConvertPtr(value, &tmp_swigpointer, SWIGTYPE_p_bro_record, 0);
      if (!SWIG_IsOK(res)) {
        SWIG_exception_fail(SWIG_ArgError(res), "the value for $symname was supposed to be a BroRecord");
      }
      $3 = (BroRecord *)(tmp_swigpointer);
      break;

    default:
      printf("ERROR($symname): no valid type defined\n");
      break;
  }
}


%typemap(out) void* bro_conn_data_get {
  if( strcmp(arg2, "service") == 0 ||
      strcmp(arg2, "addl") == 0 ||
      strcmp(arg2, "history") == 0) {
    $result = rb_str_new( (char *) bro_string_get_data((BroString*) $1),
                                   bro_string_get_length((BroString*) $1) );
  }
  else if( strcmp(arg2, "") == 0 ) {

  }
  else
  {
    printf("Couldn't find the correct data type to convert to...\n");
    $result = Qnil;
  }
}

%typemap(in) (const char *name, int *type) {
  $1 = (char*) STR2CSTR($input);
  // This is to pass arg 3 (int *type) as a value-result argument
  int mytemp3 = 0;
  $2 = &mytemp3;
}

%typemap(in) (int num, int *type) {
  $1 = NUM2INT($input);
  // This is to pass arg 3 (int *type) as a value-result argument
  int mytemp3 = 0;
  $2 = &mytemp3;
}

%typemap(out) void* bro_record_get_named_val,
              void* bro_record_get_nth_val {
  switch(*arg3)
  {
    case BRO_TYPE_BOOL:
      //printf("Ruby: Getting data matched on boolean\n");
      $result = (((int *) $1) ? Qtrue : Qfalse);
      break;

    case BRO_TYPE_INT:
    case BRO_TYPE_ENUM:
      //printf("Ruby: Getting data matched on int\n");
      $result = ULL2NUM( *((uint64 *) $1) );
      break;

    case BRO_TYPE_TIME:
    case BRO_TYPE_DOUBLE:
    case BRO_TYPE_INTERVAL:
      //printf("Ruby: Getting data matched on time\n");
      $result = rb_float_new( *((double *) $1) );
      break;

    case BRO_TYPE_STRING:
      //printf("Ruby: getting data matched on string\n");
      $result = rb_str_new( (char *)((BroString *) $1)->str_val, ((BroString *) $1)->str_len );
      break;

    case BRO_TYPE_COUNT:
      //printf("Ruby: Getting data matched on uint64\n");
      $result = ULL2NUM( *((uint64 *) $1) );
      break;

    case BRO_TYPE_IPADDR:
      //printf("I found an ip address... making it a network byte ordered string\n");
      if ( bro_util_is_v4_addr((BroAddr*) $1) )
          $result = rb_str_new((char *) (&((BroAddr *) $1)->addr[3]),
                               sizeof(uint32) );
      else
          $result = rb_str_new((char *) ((BroAddr *) $1)->addr,
                               4 * sizeof(uint32) );
      break;

    case BRO_TYPE_RECORD:
      //printf("Ruby: Getting data matched as a BroRecord\n");
      $result = SWIG_NewPointerObj(SWIG_as_voidptr( (BroRecord *) $1 ), SWIGTYPE_p_bro_record, 0);
      break;

    case BRO_TYPE_PORT:
      //printf("Ruby: Getting data matched as a BroPort\n");
      $result = SWIG_NewPointerObj(SWIG_as_voidptr( (BroPort *) $1 ), SWIGTYPE_p_bro_port, 0);
      break;

    default:
      printf("No type recognized when getting value\n");
  }
}

// When methods output an integer, it's usually boolean, make it so.
%typemap(out) int bro_conn_connect,
              int bro_conn_alive,
              int bro_conn_delete,
              int bro_conn_process_input,
              int bro_event_add_val,
              int bro_event_set_val,
              int bro_event_send,
              int bro_record_set_nth_val,
              int bro_record_set_named_val,
              int bro_packet_send "$result = $1 ? Qtrue:Qfalse;"

// Allow "true" and "false" for setting debug vars
%typemap(varin) int bro_debug_calltrace,
                int bro_debug_messages "$1 = $input ? 1:0;"

%typemap(in) uchar * "$1 = (uchar*)STR2CSTR($input);"
%typemap(out) uchar * "$result = rb_str_new2((char*)$1);"

%predicate bro_conn_alive(const BroConn *bc);

BroString to_brostring(VALUE obj);

//********************
// Header file stuff below
//********************
%include "broccoli.h"
