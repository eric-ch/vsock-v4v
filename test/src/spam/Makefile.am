COMMON_INC = -I../common/include
COMMON_LIB = 

COMMON_INCLUDES = ../common/includes/utils.h

bin_PROGRAMS = spam

spam_SOURCES = spam.c $(COMMON_INCLUDES)
spam_CFLAGS = $(COMMON_INC) -W -Wall -Werror -g
spam_CPPFLAGS = $(COMMON_INC)
spam_LDFLAGS =
spam_LDADD = -lpthread

