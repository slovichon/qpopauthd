# $Id$

TARGET = qpopauthd
OBJECTS = main.o recmanip.o report.o strlcpy.o

.c.o:
	$(CC) $(CFLAGS) -c $< -o $*.o

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $(TARGET) $(OBJECTS)

clean:
	$(RM) $(TARGET) $(OBJECTS)
