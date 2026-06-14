import os
from datetime import datetime
import uuid

try:
    from opensearchpy import AsyncOpenSearch
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False
    print("⚠️  opensearch-py package not found. Using in-memory storage.")

INDEX_NAME = "network_logs"
INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "log_id":             {"type": "keyword"},
            "user_email":         {"type": "keyword"},
            "timestamp":          {"type": "date"},
            "is_threat":          {"type": "boolean"},
            "attack_type":        {"type": "keyword"},
            "threat_score":       {"type": "float"},
            "confidence":         {"type": "float"},
            "mitre_technique_id": {"type": "keyword"},
            "mitre_tactic":       {"type": "keyword"},
            "shap_top_feature":   {"type": "keyword"},
            "log_data":           {"type": "object"},
        }
    }
}


class InMemoryStorage:
    def __init__(self):
        self.logs = []

    async def create_index(self):
        print("📦 Using in-memory storage (no ES/Bonsai configured)")

    async def index_log(self, result: dict, user_email: str = ""):
        entry = {
            "log_id":     str(uuid.uuid4()),
            "user_email": user_email,
            "timestamp":  result.get("timestamp", datetime.now().isoformat()),
            **result
        }
        self.logs.append(entry)
        if len(self.logs) > 1000:
            self.logs.pop(0)

    async def get_recent_logs(self, size: int = 50, user_email: str = "") -> list:
        if not user_email:
            return []
        filtered = [l for l in self.logs if l.get("user_email") == user_email]
        return filtered[-size:][::-1]

    async def delete_log(self, log_id: str, es_id: str = "", user_email: str = "") -> bool:
        """
        Always enforces user_email ownership — even when es_id is supplied.
        A log is only deleted if BOTH the ID matches AND it belongs to the
        requesting user. Passing es_id without a matching user_email is denied.
        """
        if not user_email:
            return False

        before = len(self.logs)
        self.logs = [
            l for l in self.logs
            if not (
                (l.get("log_id") == log_id or l.get("_es_id") == es_id)
                and l.get("user_email") == user_email   # ownership always checked
            )
        ]
        return len(self.logs) < before

    async def delete_all_logs(self, user_email: str = "") -> int:
        """
        Only deletes logs belonging to the requesting user.
        An empty user_email is rejected — never wipes all logs.
        """
        if not user_email:
            # FIX: previously this branch wiped ALL logs when user_email was empty.
            # Now it is a hard no-op so an unauthenticated call cannot nuke the store.
            return 0

        before = len(self.logs)
        self.logs = [l for l in self.logs if l.get("user_email") != user_email]
        return before - len(self.logs)

    async def get_stats(self, user_email: str = "") -> dict:
        if not user_email:
            return {
                "total_logs": 0, "total_threats": 0,
                "attack_distribution": {}, "detection_rate": 0
            }
        logs    = [l for l in self.logs if l.get("user_email") == user_email]
        total   = len(logs)
        threats = sum(1 for l in logs if l.get("is_threat"))
        attack_counts = {}
        for log in logs:
            at = log.get("attack_type", "Unknown")
            attack_counts[at] = attack_counts.get(at, 0) + 1
        return {
            "total_logs":          total,
            "total_threats":       threats,
            "attack_distribution": attack_counts,
            "detection_rate":      round(threats / total * 100, 2) if total > 0 else 0
        }


class ElasticsearchClient:

    def __init__(self):
        self._fallback = InMemoryStorage()
        self.use_es    = False
        self.es        = None

        if not ES_AVAILABLE:
            return

        host = (
            os.getenv("ES_HOST", "").strip() or
            os.getenv("ES_LOCAL_HOST", "").strip() or
            "http://localhost:9200"
        )

        try:
            self.es = AsyncOpenSearch(
                hosts=[host],
                use_ssl="https://" in host,
                verify_certs=True,
                ssl_show_warn=False,
            )
            self.use_es = True
            source = "Bonsai" if "bonsaisearch.net" in host else "local"
            print(f"✅ OpenSearch client initialized ({source})")
        except Exception as e:
            print(f"⚠️  Elasticsearch init failed: {e}. Using in-memory.")
            self.use_es = False

    async def create_index(self):
        if self.use_es:
            try:
                exists = await self.es.indices.exists(index=INDEX_NAME)
                if not exists:
                    await self.es.indices.create(index=INDEX_NAME, body=INDEX_MAPPING)
                    print(f"✅ ES index '{INDEX_NAME}' created")
                return
            except Exception as e:
                print(f"⚠️  ES index error: {e}. Falling back to memory.")
                self.use_es = False
        await self._fallback.create_index()

    async def index_log(self, result: dict, user_email: str = ""):
        doc = {
            "log_id":             str(uuid.uuid4()),
            "user_email":         user_email,
            "timestamp":          result.get("timestamp", datetime.now().isoformat()),
            "is_threat":          result.get("is_threat"),
            "attack_type":        result.get("attack_type"),
            "threat_score":       result.get("threat_score"),
            "confidence":         result.get("confidence"),
            "mitre_technique_id": result.get("mitre", {}).get("technique_id"),
            "mitre_tactic":       result.get("mitre", {}).get("tactic"),
            "shap_top_feature":   result.get("shap_values", {}).get("top_features", [{}])[0].get("feature"),
            "log_data":           result.get("log_data", {}),
            "shap_values":        result.get("shap_values"),
            "mitre":              result.get("mitre"),
        }
        if self.use_es:
            try:
                res = await self.es.index(index=INDEX_NAME, body=doc)
                doc["_es_id"] = res["_id"]
                return
            except Exception as e:
                print(f"⚠️  ES index_log failed: {e}. Falling back to in-memory for this entry.")
        await self._fallback.index_log(result, user_email)

    async def get_recent_logs(self, size: int = 50, user_email: str = "") -> list:
        if not user_email:
            return []
        if self.use_es:
            try:
                query  = {"term": {"user_email": user_email}}
                result = await self.es.search(
                    index=INDEX_NAME,
                    body={"query": query, "sort": [{"timestamp": "desc"}], "size": size}
                )
                logs = []
                for hit in result["hits"]["hits"]:
                    entry = hit["_source"]
                    entry["_es_id"] = hit["_id"]
                    logs.append(entry)
                return logs
            except Exception as e:
                print(f"⚠️  ES get_recent_logs failed: {e}. Falling back to memory.")
        return await self._fallback.get_recent_logs(size, user_email)

    async def delete_log(self, log_id: str, es_id: str = "", user_email: str = "") -> bool:
        """
        FIX #5: Ownership is ALWAYS enforced, even when es_id is provided.

        Previously when es_id was supplied, the code did:
            self.es.delete(index=INDEX_NAME, id=es_id)
        with no user_email check — any authenticated user could delete
        anyone else's document by guessing or observing an es_id.

        Now we ALWAYS use delete_by_query with both the document ID
        AND the user_email in the must clause, regardless of which ID
        type was supplied. This means the document is only deleted if
        it belongs to the requesting user.
        """
        if not user_email:
            return False

        if self.use_es:
            try:
                # Build the must clause — always include user_email for ownership
                must = [{"term": {"user_email": user_email}}]

                if es_id:
                    # Use _id filter to match the Elasticsearch internal document ID
                    must.append({"ids": {"values": [es_id]}})
                else:
                    # Fall back to matching on our application-level log_id field
                    must.append({"term": {"log_id": log_id}})

                result = await self.es.delete_by_query(
                    index=INDEX_NAME,
                    body={"query": {"bool": {"must": must}}}
                )
                deleted_count = result.get("deleted", 0)
                return deleted_count > 0

            except Exception as e:
                print(f"⚠️  ES delete_log failed: {e}. Falling back to memory.")

        return await self._fallback.delete_log(log_id, es_id, user_email)

    async def delete_all_logs(self, user_email: str = "") -> int:
        """
        Only deletes logs belonging to the requesting user.
        Rejects empty user_email — never issues a delete-all query.
        """
        if not user_email:
            return 0

        if self.use_es:
            try:
                query  = {"term": {"user_email": user_email}}
                result = await self.es.delete_by_query(
                    index=INDEX_NAME,
                    body={"query": query}
                )
                return result.get("deleted", 0)
            except Exception as e:
                print(f"⚠️  ES delete_all_logs failed: {e}. Falling back to memory.")

        return await self._fallback.delete_all_logs(user_email)

    async def get_stats(self, user_email: str = "") -> dict:
        if not user_email:
            return {
                "total_logs": 0, "total_threats": 0,
                "attack_distribution": {}, "detection_rate": 0
            }
        if self.use_es:
            try:
                query  = {"term": {"user_email": user_email}}
                result = await self.es.search(
                    index=INDEX_NAME,
                    body={
                        "query": query,
                        "aggs": {
                            "total":        {"value_count": {"field": "log_id"}},
                            "threats":      {"filter": {"term": {"is_threat": True}}},
                            "attack_types": {"terms": {"field": "attack_type", "size": 20}}
                        },
                        "size": 0
                    }
                )
                aggs    = result["aggregations"]
                total   = aggs["total"]["value"]
                threats = aggs["threats"]["doc_count"]
                attack_dist = {
                    b["key"]: b["doc_count"]
                    for b in aggs["attack_types"]["buckets"]
                }
                return {
                    "total_logs":          total,
                    "total_threats":       threats,
                    "attack_distribution": attack_dist,
                    "detection_rate":      round(threats / total * 100, 2) if total > 0 else 0
                }
            except Exception as e:
                print(f"⚠️  ES get_stats failed: {e}. Falling back to memory.")

        return await self._fallback.get_stats(user_email)