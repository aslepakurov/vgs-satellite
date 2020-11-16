from base58 import b58encode
from abc import abstractmethod, ABCMeta


class AliasGenerator(metaclass=ABCMeta):
    @abstractmethod
    def generate(self, value):
        pass


class UUIDAliasGenerator(AliasGenerator):
    def generate(self, value):
        return f'tok_sat_{b58encode(value).decode("UTF-8")}'[:30]


generator_map = {
    'UUID': UUIDAliasGenerator()
}
