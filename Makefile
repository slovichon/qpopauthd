# $Id$

TARGET = qpopauthd
OBJECTS = main.o session.o
CFLAGS = -Wall

.c.o:
	$(CC) $(CFLAGS) -c $<

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $(TARGET) $(OBJECTS)

clean:
	$(RM) $(TARGET) $(OBJECTS)
