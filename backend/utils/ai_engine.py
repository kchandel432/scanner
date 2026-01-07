import pickle
import numpy as np
from pathlib import Path
from typing import Dict, Any, Optional
import torch
import torch.nn as nn
from transformers import AutoModel, AutoTokenizer
import onnxruntime as ort

class AIEngine:
    """Central AI engine for all models"""
    
    _instance = None
    models_loaded = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(AIEngine, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.models = {}
            self.initialized = False
    
    @classmethod
    def load_models(cls):
        """Load all AI models"""
        instance = cls()
        
        # Load malware detection model
        malware_model_path = Path("ml_models/malware_detector/model.onnx")
        if malware_model_path.exists():
            instance.models["malware"] = ort.InferenceSession(str(malware_model_path))
        
        # Load website classifier
        website_model_path = Path("ml_models/website_classifier/model.pth")
        if website_model_path.exists():
            instance.models["website"] = torch.load(website_model_path, map_location='cpu')
            instance.models["website"].eval()
        
        # Load NLP model for content analysis
        try:
            instance.models["nlp"] = AutoModel.from_pretrained("distilbert-base-uncased")
            instance.models["nlp_tokenizer"] = AutoTokenizer.from_pretrained("distilbert-base-uncased")
        except:
            pass
        
        instance.initialized = True
        cls.models_loaded = True
        return instance
    
    def predict_malware(self, features: np.ndarray) -> Dict[str, Any]:
        """Predict if file is malware"""
        if "malware" not in self.models:
            return {"score": 0.0, "confidence": 0.0}
        
        try:
            input_name = self.models["malware"].get_inputs()[0].name
            output_name = self.models["malware"].get_outputs()[0].name
            
            # Prepare input
            features = features.astype(np.float32).reshape(1, -1)
            
            # Run inference
            prediction = self.models["malware"].run(
                [output_name], {input_name: features}
            )[0][0]
            
            # Get confidence scores
            confidence = float(prediction[1]) if len(prediction) > 1 else float(prediction[0])
            
            return {
                "score": float(prediction[0]),
                "confidence": confidence,
                "is_malware": confidence > 0.7
            }
            
        except Exception as e:
            return {"error": str(e), "score": 0.0, "confidence": 0.0}
    
    def classify_website(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Classify website threat level"""
        if "website" not in self.models:
            return {"threat_level": "unknown", "confidence": 0.0}
        
        try:
            # Convert features to tensor
            feature_tensor = self._prepare_features(features)
            
            # Get prediction
            with torch.no_grad():
                output = self.models["website"](feature_tensor)
                probabilities = torch.nn.functional.softmax(output, dim=1)
                
                threat_levels = ["clean", "low", "medium", "high", "critical"]
                pred_idx = torch.argmax(probabilities, dim=1).item()
                confidence = probabilities[0][pred_idx].item()
                
                return {
                    "threat_level": threat_levels[pred_idx],
                    "confidence": confidence,
                    "probabilities": probabilities.numpy().tolist()
                }
                
        except Exception as e:
            return {"error": str(e), "threat_level": "unknown", "confidence": 0.0}
    
    def analyze_content(self, text: str) -> Dict[str, Any]:
        """Analyze text content for threats"""
        if "nlp" not in self.models:
            return {"risk_score": 0.0, "categories": []}
        
        try:
            # Tokenize text
            inputs = self.models["nlp_tokenizer"](
                text, 
                return_tensors="pt", 
                truncation=True, 
                max_length=512
            )
            
            # Get embeddings
            with torch.no_grad():
                outputs = self.models["nlp"](**inputs)
                embeddings = outputs.last_hidden_state.mean(dim=1)
            
            # Simple heuristic analysis (replace with trained classifier)
            suspicious_terms = [
                "password", "login", "account", "verify", "secure",
                "bank", "paypal", "credit", "card", "social security"
            ]
            
            risk_score = 0.0
            detected_terms = []
            
            for term in suspicious_terms:
                if term in text.lower():
                    risk_score += 0.05
                    detected_terms.append(term)
            
            return {
                "risk_score": min(risk_score, 1.0),
                "suspicious_terms": detected_terms,
                "embedding": embeddings.numpy().tolist()
            }
            
        except Exception as e:
            return {"error": str(e), "risk_score": 0.0}
    
    def _prepare_features(self, features: Dict[str, Any]) -> torch.Tensor:
        """Prepare features for model input"""
        # Extract relevant features
        feature_list = []
        
        # SSL features
        ssl_info = features.get("ssl_info", {})
        feature_list.append(1.0 if ssl_info.get("has_ssl") else 0.0)
        feature_list.append(1.0 if ssl_info.get("has_expired") else 0.0)
        feature_list.append(1.0 if ssl_info.get("is_self_signed") else 0.0)
        
        # Security headers score
        headers = features.get("security_headers", {})
        feature_list.append(headers.get("score", 0.0) / 100.0)
        
        # Domain age (normalized)
        domain_info = features.get("domain_info", {})
        age_days = domain_info.get("domain_age_days", 365)
        feature_list.append(min(age_days / 365, 1.0))
        
        # Convert to tensor
        return torch.tensor([feature_list], dtype=torch.float32)
