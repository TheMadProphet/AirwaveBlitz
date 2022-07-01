from dataclasses import dataclass, field
from typing import Dict, Generic, TypeVar


class EntityNotFoundException(Exception):
    pass


T = TypeVar("T")


@dataclass
class EntityRepository(Generic[T]):
    entities: Dict[str, T] = field(default_factory=dict)

    def find(self, entity_id: str) -> T:
        if entity_id not in self.entities:
            raise EntityNotFoundException

        return self.entities[entity_id]

    def find_all(self) -> Dict[str, T]:
        return self.entities

    def save(self, entity_id: str, entity: T) -> None:
        self.entities[entity_id] = entity

    def delete(self, entity_id: str) -> None:
        if entity_id not in self.entities:
            raise EntityNotFoundException

        del self.entities[entity_id]

    def delete_all(self) -> None:
        self.entities = dict()
