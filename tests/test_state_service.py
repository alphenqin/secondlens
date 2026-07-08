from app.services.task_service import ProcessedTaskStore


def test_processed_task_store_persists_keys(tmp_path):
    path = tmp_path / "processed_tasks.json"
    store = ProcessedTaskStore(path)

    assert not store.contains("20260707/123/secon_analysis_123.json")

    store.add("20260707/123/secon_analysis_123.json")
    reloaded = ProcessedTaskStore(path)

    assert reloaded.contains("20260707/123/secon_analysis_123.json")
