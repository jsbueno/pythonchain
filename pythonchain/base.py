"""
Provides a base class to serialize well behaved Python objects,
with data fields, as well-defined byte-sequences.
"""

from collections import OrderedDict

def _init_field_dictionary(cls):
    cls.fields = OrderedDict()
    # fetch all fields in superclasses, in reverse order
    # skipíng itself and object (the root):
    for supercls in cls.__mro__[-1:1:-1]:
        for field_name, value in cls.__dict__.get("fields", {}).items():
            cls.fields[field_name] = value

class Field:
    type = type(None)

    def __init__(self, default=None):
        self.default = default

    def __get__(self, instance, owner=None):
        if not instance:
            return self
        return instance.__dict__.get(self.name, self.default)

    def __set__(self, instance, value):
        if not isinstance(value, self.type):
            raise TypeError(f"Attribute '{self.name}' must be a '{self.type.__name__}' instance")
        instance.__dict__[self.name] = value

    def __set_name__(self, owner, name):
        self.name = name
        # Ensure each field-containing class has its own 'fields'
        # instance (regardless of superclasses)
        if not "fields" in owner.__dict__:
            _init_field_dictionary(owner)
        owner.fields[self.name] = self

    def serialize(self, instance):
        """returns a representation of self as bytes"""
        return b""

    @classmethod
    def import_(cls, data, offset=0)->(object, int):
        """Return data that can be set as this field content

        given a bytes-like object, and an offset to the data
        inside it
        """
        # Default "nonetype" fields take no space
        # on the serialized stream
        return None, offset


NoneField = Field

class Int(Field):
    type = int
    data_size = 8
    neg = False

    def __init__(self, default=0):
        super().__init__(default)

    def __set__(self, instance, value):
        if self.__class__.neg:
            value = ~value
        if value >= 2 ** (8 * self.__class__.data_size):
            raise ValueError("Value too big")
        super().__set__(instance, value)

    def serialize(self, instance):
       return self.__get__(instance).to_bytes(self.__class__.data_size, "little")

    @classmethod
    def import_(cls, data ,offset=0):
        op = (lambda i: ~i) if cls.neg else (lambda i: i)
        return op(int.from_bytes(data[offset: offset + cls.data_size], "little")), offset + cls.data_size

UInt64 = Int

class Int64(Int):
    neg = True

class Int32(Int):
    data_size = 4
    neg = True

class UInt32(Int):
    data_size = 4

class Int16(Int):
    data_size = 2
    neg = True

class UInt16(Int):
    data_size = 2

class UInt8(Int):
    data_size = 1

Byte = UInt8


class String(Field):
    type = str
    encoding = "utf-8"
    len_bytes = 2

    def __init__(self, default=""):
        super().__init__(default)

    def __set__(self, instance, value):
        cls = self.__class__
        if len(value.encode(cls.encoding)) >= 2 ** (8 * cls.len_bytes):
            raise ValueError("Text too big")
        super().__set__(instance, value)

    def serialize(self, instance):
        cls = self.__class__
        value = self.__get__(instance).encode(cls.encoding)
        return len(value).to_bytes(self.len_bytes, "little") + value

    @classmethod
    def import_(cls, data ,offset=0):
        start_pos = offset + cls.len_bytes
        length = int.from_bytes(data[offset: start_pos], "little")
        end_pos = start_pos + length
        raw = data[start_pos: end_pos]
        return raw.decode(cls.encoding), end_pos


class Base:

    def __init__(self, **kwargs):
        super().__init__()
        for name, value in kwargs.items():
            if name not in self.fields:
                raise TypeError(f"Attribute '{name}' not reconized for this object")
            setattr(self, name, value)

    def serialize(self):
        cls = self.__class__
        state = bytearray()
        for fieldname, field in cls.fields.items():
            state += field.serialize(self)
        return bytes(state)

    @classmethod
    def from_data(cls, data):
        self = cls()
        offset = 0
        for field_name, field in cls.fields.items():
            field_data, offset = field.import_(data, offset)
            setattr(self, field_name, field_data)
        return self

class Test0(Base):
    a = Field()
    b = Field()
    c = UInt8()
    d = UInt64()
    e = String()



