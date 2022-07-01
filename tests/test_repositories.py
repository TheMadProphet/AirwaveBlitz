import pytest

from app.entities.handshake import Handshake
from app.repository.entity_repository import EntityNotFoundException, EntityRepository
from app.repository.handshake_repository import HandshakeRepository


def test_entity_repository_creation() -> None:
    assert EntityRepository() is not None


def test_entity_repository_save_and_find() -> None:
    age_repository: EntityRepository[int] = EntityRepository()

    age_repository.save("bob", 25)
    age_repository.save("dylan", 14)
    age_repository.save("robert", 33)

    assert age_repository.find("bob") == 25
    assert age_repository.find("dylan") == 14
    assert age_repository.find("robert") == 33


def test_entity_repository_modify() -> None:
    age_repository: EntityRepository[int] = EntityRepository()

    age_repository.save("bob", 10)
    age_repository.save("bob", 33)

    assert age_repository.find("bob") == 33


def test_entity_repository_delete() -> None:
    age_repository: EntityRepository[int] = EntityRepository()
    age_repository.save("bob", 7)
    age_repository.save("dylan", 7)

    age_repository.delete("dylan")
    with pytest.raises(EntityNotFoundException):
        age_repository.find("dylan")

    assert age_repository.find("bob") == 7


def test_entity_repository_delete_all() -> None:
    age_repository: EntityRepository[int] = EntityRepository()

    age_repository.save("bob", 25)
    age_repository.save("dylan", 14)
    age_repository.save("robert", 33)

    assert len(age_repository.find_all()) == 3
    age_repository.delete_all()
    assert len(age_repository.find_all()) == 0


def test_handshake_repository() -> None:
    handshakes = HandshakeRepository()

    handshakes.save("mac1", "bssid1", Handshake())
    handshakes.save("mac2", "bssid1", Handshake())
    handshakes.save("mac3", "bssid2", Handshake())

    assert handshakes.find("mac1", "bssid1") is not None
    assert handshakes.find("mac2", "bssid1") is not None
    assert handshakes.find("mac3", "bssid2") is not None

    assert len(handshakes.find_all_for_ap("bssid1")) == 2
    assert len(handshakes.find_all_for_ap("bssid2")) == 1

    assert handshakes.find_captured_for_ap("bssid1") is None
    assert handshakes.find_captured_for_ap("bssid2") is None
