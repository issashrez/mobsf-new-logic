import math
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from datetime import datetime


@dataclass
class Vulnerability:
    name: str
    cvss_score: float
    description: str
    remediation: str

@dataclass
class SecurityControl:
    name: str
    implemented: bool

class ImprovedMobSFScoring:
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.security_controls: List[SecurityControl] = []
        self.attack_surface_complexity: int = 1
        self.code_quality_metrics: Dict[str, float] = {}
        self.update_frequency: int = 1
        self.weight_vi: float = 0.4
        self.weight_asc: float = 5
        self.weight_sci: float = 0.2
        self.weight_cqs: float = 0.2
        self.weight_uf: float = 2

    def add_vulnerability(self, vuln: Vulnerability):
        self.vulnerabilities.append(vuln)

    def set_attack_surface_complexity(self, complexity: int):
        if 1 <= complexity <= 5:
            self.attack_surface_complexity = complexity
        else:
            raise ValueError("Attack Surface Complexity must be between 1 and 5")

    def add_security_control(self, control: SecurityControl):
        self.security_controls.append(control)

    def set_code_quality_metrics(self, metrics: Dict[str, float]):
        self.code_quality_metrics = metrics

    def set_update_frequency(self, frequency: int):
        if 1 <= frequency <= 5:
            self.update_frequency = frequency
        else:
            raise ValueError("Update Frequency must be between 1 and 5")

    def calculate_vulnerability_impact(self) -> float:
        return sum(vuln.cvss_score for vuln in self.vulnerabilities)

    def calculate_security_controls_implementation(self) -> float:
        if not self.security_controls:
            return 0
        implemented = sum(1 for control in self.security_controls if control.implemented)
        return (implemented / len(self.security_controls)) * 100

    def calculate_code_quality_score(self) -> float:
        if not self.code_quality_metrics:
            return 0
        return 100 - (sum(self.code_quality_metrics.values()) / len(self.code_quality_metrics))

    def calculate_app_security_score(self) -> float:
        vi = self.calculate_vulnerability_impact()
        asc = self.attack_surface_complexity
        sci = self.calculate_security_controls_implementation()
        cqs = self.calculate_code_quality_score()
        uf = self.update_frequency

        score = 100 - (vi * self.weight_vi) + (asc * self.weight_asc) + \
                (sci * self.weight_sci) + (cqs * self.weight_cqs) + (uf * self.weight_uf)
        
        return max(0, min(100, score))

    def get_risk_level_and_grade(self, score: float) -> Tuple[str, str]:
        if score >= 90:
            return "Very Low", "A+"
        elif score >= 80:
            return "Low", "A"
        elif score >= 70:
            return "Low-Medium", "B+"
        elif score >= 60:
            return "Medium", "B"
        elif score >= 50:
            return "Medium-High", "C+"
        elif score >= 40:
            return "High", "C"
        elif score >= 30:
            return "Very High", "D"
        else:
            return "Critical", "F"

    def generate_report(self) -> Dict[str, Any]:
        score = self.calculate_app_security_score()
        risk_level, grade = self.get_risk_level_and_grade(score)
        
        return {
            "overall_score": score,
            "risk_level": risk_level,
            "grade": grade,
            "vulnerability_impact": self.calculate_vulnerability_impact(),
            "attack_surface_complexity": self.attack_surface_complexity,
            "security_controls_implementation": self.calculate_security_controls_implementation(),
            "code_quality_score": self.calculate_code_quality_score(),
            "update_frequency": self.update_frequency,
            "vulnerabilities": [
                {
                    "name": vuln.name,
                    "cvss_score": vuln.cvss_score,
                    "risk_level": self.get_risk_level(vuln.cvss_score),
                    "description": vuln.description,
                    "remediation": vuln.remediation
                } for vuln in self.vulnerabilities
            ],
            "security_controls": [
                {
                    "name": control.name,
                    "implemented": control.implemented
                } for control in self.security_controls
            ]
        }

    @staticmethod
    def get_risk_level(cvss_score: float) -> str:
        if cvss_score >= 9.0:
            return "Critical"
        elif cvss_score >= 7.0:
            return "High"
        elif cvss_score >= 4.0:
            return "Medium"
        elif cvss_score > 0.0:
            return "Low"
        else:
            return "None"

class TrendAnalysis:
    def __init__(self):
        self.historical_scores: List[Tuple[datetime, float]] = []

    def add_score(self, date: datetime, score: float):
        self.historical_scores.append((date, score))

    def calculate_trend(self) -> float:
        if len(self.historical_scores) < 2:
            return 0
        
        sorted_scores = sorted(self.historical_scores, key=lambda x: x[0])
        first_score = sorted_scores[0][1]
        last_score = sorted_scores[-1][1]
        time_diff = (sorted_scores[-1][0] - sorted_scores[0][0]).days

        return (last_score - first_score) / time_diff

class ComplianceChecker:
    def __init__(self):
        self.compliance_frameworks: Dict[str, List[str]] = {
            "OWASP MASVS": ["V1: Architecture, Design and Threat Modeling Requirements",
                            "V2: Data Storage and Privacy Requirements",
                            "V3: Cryptography Requirements",
                            "V4: Authentication and Session Management Requirements",
                            "V5: Network Communication Requirements",
                            "V6: Platform Interaction Requirements",
                            "V7: Code Quality and Build Setting Requirements",
                            "V8: Resilience Requirements"],
            "GDPR": ["Data Protection by Design and Default",
                     "Data Subject Rights",
                     "Consent Management",
                     "Data Breach Notification",
                     "Data Protection Impact Assessment"],
            "PCI DSS": ["Protect stored cardholder data",
                        "Encrypt transmission of cardholder data across open, public networks",
                        "Protect against malware",
                        "Develop and maintain secure systems and applications",
                        "Restrict access to cardholder data by business need to know"]
        }

    def check_compliance(self, framework: str, implemented_controls: List[str]) -> Dict[str, bool]:
        if framework not in self.compliance_frameworks:
            raise ValueError(f"Unknown compliance framework: {framework}")
        
        return {control: control in implemented_controls 
                for control in self.compliance_frameworks[framework]}

scorer = ImprovedMobSFScoring()

scorer.add_vulnerability(Vulnerability("SQL Injection", 7.5, "SQL injection vulnerability in login form", "Use prepared statements"))
scorer.add_vulnerability(Vulnerability("Insecure Data Storage", 6.5, "Sensitive data stored in SharedPreferences", "Use Android Keystore for sensitive data"))

scorer.set_attack_surface_complexity(3)

scorer.add_security_control(SecurityControl("Certificate Pinning", True))
scorer.add_security_control(SecurityControl("Biometric Authentication", False))

scorer.set_code_quality_metrics({"cyclomatic_complexity": 15, "code_duplication": 5})

scorer.set_update_frequency(4)

report = scorer.generate_report()
print(f"App Security Score: {report['overall_score']:.2f}")
print(f"Risk Level: {report['risk_level']}")
print(f"Grade: {report['grade']}")

trend_analyzer = TrendAnalysis()
trend_analyzer.add_score(datetime(2023, 1, 1), 65)
trend_analyzer.add_score(datetime(2023, 4, 1), 72)
trend_analyzer.add_score(datetime(2023, 7, 1), 78)
print(f"Security Score Trend: {trend_analyzer.calculate_trend():.2f} points per day")

compliance_checker = ComplianceChecker()
implemented_controls = ["V2: Data Storage and Privacy Requirements", "V3: Cryptography Requirements"]
owasp_masvs_compliance = compliance_checker.check_compliance("OWASP MASVS", implemented_controls)
print("OWASP MASVS Compliance:")
for control, compliant in owasp_masvs_compliance.items():
    print(f"  {control}: {'Compliant' if compliant else 'Non-compliant'}")
