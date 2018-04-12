"""
Provides a base class to serialize well behaved Python objects,
with data fields, as well-defined byte-sequences.
"""

from collections import OrderedDict
from collections.abc import MutableSequence, Sequence, Iterable

from decimal import Decimal as _Decimal

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


class Decimal(String):

    def __init__(self, default="0"):
        super().__init__(default)

    def __set__(self, instance, value):
        if isinstance(value, float):
            value = str(value)
        x = _Decimal(value)  #  noQA - Just for checking if it is a well formed decimal.
        super().__set__(instance, str(value))

    def __get__(self, instance, owner=None):
        value = super().__get__(instance, owner)
        if owner:
            return _Decimal(super().__get__(instance, owner))
        # else: owner == None implies we are called from the serializer
        return value


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
    def from_data(cls, data, offset=0):
        self = cls()
        for field_name, field in cls.fields.items():
            field_data, offset = field.import_(data, offset)
            setattr(self, field_name, field_data)
        # optional state, used when objects are restored in sequence
        # from an outer stream
        self._offset = offset
        return self


def sequence_factory(sequence_type):
    class InnerSequence(MutableSequence):
        maxlen = 2 ** 16

        def __init__(self):
            self.type = sequence_type
            self.data = []

        def __getitem__(self, index):
            return self.data[index]

        def __setitem__(self, index, value):
            if not isinstance(value, self.type):
                raise TypeError(f"Items must be instances of '{self.type.__name__}'")
            self.data[index] = value

        def __delitem__(self, index):
            del self.data[index]

        def __len__(self):
            return len(self.data)

        def insert(self, index, value):
            if not isinstance(value, self.type):
                raise TypeError(f"Items must be instances of '{self.type.__name__}'")
            if index >= self.maxlen:
                raise IndexError(f"Maximum number of itens is {self.maxlen}")
            self.data.insert(index, value)

        def fill(self, sequence):
            self.data[:] = []
            for value in sequence:
                self.append(value)

        def __repr__(self):
            return repr(self.data)

    return InnerSequence


type_ = type

class SequenceField(Field):
    """Allows a sequence of Base models to be used as a field"""
    type = None
    len_bytes = 2

    def __init__(self, type, default=None):
        if not issubclass(type, Base):
            raise TypeError("Types for sequence should be a Base type. Add fields to it")
        self.type = type
        super().__init__(default=sequence_factory(type))
        self._initialized = True

    def __get__(self, instance, owner=None):
        if not instance:
            return self
        return instance.__dict__.setdefault(self.name, self.default())

    def __set__(self, instance, value):
        if not isinstance(value, (Sequence, Iterable)):
            raise TypeError("This field can only be set to a sequence of '{self.type.__name__}' objects")
        self.__get__(instance).fill(value)

    def serialize(self, instance):
        """returns a representation of self as bytes"""
        if issubclass(self.type, Base):
            data = self.__get__(instance)
            return len(data).to_bytes(self.len_bytes, "little") + b"".join(obj.serialize() for obj in data)
        raise NotImplementedError # Todo: allow items to be Fields, instead of just Base objects


    def import_(self, data, offset=0)->(object, int):
        """Return data that can be set as this field content
        """
        cls = self.__class__
        start_pos = offset + cls.len_bytes
        length = int.from_bytes(data[offset: start_pos], "little")
        offset += cls.len_bytes
        result = []
        for i in range(length):
            result.append(self.type.from_data(data, offset))
            offset = result[-1]._offset

        return result, offset



class Test0(Base):
    a = Field()
    b = Field()
    c = UInt8()
    d = UInt64()
    e = String()
    f = Decimal()

class Test1(Base):
    g = SequenceField(Test0)


