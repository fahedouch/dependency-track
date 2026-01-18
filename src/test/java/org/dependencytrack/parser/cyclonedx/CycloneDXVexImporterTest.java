package org.dependencytrack.parser.cyclonedx;

import org.assertj.core.api.Assertions;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.parsers.BomParserFactory;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.jupiter.api.Test;

import javax.jdo.Query;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

class CycloneDXVexImporterTest extends PersistenceCapableTest {

    private CycloneDXVexImporter vexImporter = new CycloneDXVexImporter();

    @Test
    void shouldAuditVulnerabilityFromAllSourcesUsingVex() throws URISyntaxException, IOException, ParseException {
        // Arrange
        var sources = Arrays.asList(Vulnerability.Source.values());
        var project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        final byte[] vexBytes = Files.readAllBytes(Paths.get(getClass().getClassLoader().getResource("vex-1.json").toURI()));
        var parser = BomParserFactory.createParser(vexBytes);
        var vex = parser.parse(vexBytes);

        List<org.cyclonedx.model.vulnerability.Vulnerability> audits = new LinkedList<>();

        var unknownVexSourceVulnerability = new Vulnerability();
        unknownVexSourceVulnerability.setVulnId("CVE-2020-25649");
        unknownVexSourceVulnerability.setSource(Vulnerability.Source.NVD);
        unknownVexSourceVulnerability.setSeverity(Severity.HIGH);
        unknownVexSourceVulnerability.setComponents(List.of(component));
        unknownVexSourceVulnerability = qm.createVulnerability(unknownVexSourceVulnerability, false);
        qm.addVulnerability(unknownVexSourceVulnerability, component, AnalyzerIdentity.NONE);

        var mismatchVexSourceVulnerability = new Vulnerability();
        mismatchVexSourceVulnerability.setVulnId("CVE-2020-25650");
        mismatchVexSourceVulnerability.setSource(Vulnerability.Source.NVD);
        mismatchVexSourceVulnerability.setSeverity(Severity.HIGH);
        mismatchVexSourceVulnerability.setComponents(List.of(component));
        mismatchVexSourceVulnerability = qm.createVulnerability(mismatchVexSourceVulnerability, false);
        qm.addVulnerability(mismatchVexSourceVulnerability, component, AnalyzerIdentity.NONE);

        var noVexSourceVulnerability = new Vulnerability();
        noVexSourceVulnerability.setVulnId("CVE-2020-25651");
        noVexSourceVulnerability.setSource(Vulnerability.Source.GITHUB);
        noVexSourceVulnerability.setSeverity(Severity.HIGH);
        noVexSourceVulnerability.setComponents(List.of(component));
        noVexSourceVulnerability = qm.createVulnerability(noVexSourceVulnerability, false);
        qm.addVulnerability(noVexSourceVulnerability, component, AnalyzerIdentity.NONE);

        // Build vulnerabilities for each available and known vulnerability source
        for (var source : sources) {
            var vulnId = source.name().toUpperCase()+"-001";
            var vulnerability = new Vulnerability();
            vulnerability.setVulnId(vulnId);
            vulnerability.setSource(source);
            vulnerability.setSeverity(Severity.HIGH);
            vulnerability.setComponents(List.of(component));
            vulnerability = qm.createVulnerability(vulnerability, false);
            qm.addVulnerability(vulnerability, component, AnalyzerIdentity.NONE);

            var audit = new org.cyclonedx.model.vulnerability.Vulnerability();
            audit.setBomRef(UUID.randomUUID().toString());
            audit.setId(vulnId);
            var auditSource = new org.cyclonedx.model.vulnerability.Vulnerability.Source();
            auditSource.setName(source.name());
            audit.setSource(auditSource);
            var analysis = new org.cyclonedx.model.vulnerability.Vulnerability.Analysis();
            analysis.setState(org.cyclonedx.model.vulnerability.Vulnerability.Analysis.State.FALSE_POSITIVE);
            analysis.setDetail("Unit test");
            analysis.setJustification(org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification.PROTECTED_BY_MITIGATING_CONTROL);
            audit.setAnalysis(analysis);
            var affect = new org.cyclonedx.model.vulnerability.Vulnerability.Affect();
            affect.setRef(vex.getMetadata().getComponent().getBomRef());
            audit.setAffects(List.of(affect));
            audits.add(audit);
        }
        audits.addAll(vex.getVulnerabilities());
        vex.setVulnerabilities(audits);
        qm.getPersistenceManager().refreshAll();

        // Act
        vexImporter.applyVex(qm, vex, project);

        // Assert
        final Query<Analysis> query = qm.getPersistenceManager().newQuery(Analysis.class, "project == :project");
        query.setParameters(project);
        final List<Analysis> analyses = query.executeList();
        // CVE-2020-256[49|50|51] are not audited otherwise analyses.size would have been equal to sources.size()+3
        org.junit.jupiter.api.Assertions.assertEquals(sources.size(), analyses.size());
        Assertions.assertThat(analyses).allSatisfy(analysis -> {
            Assertions.assertThat(analysis.getVulnerability().getVulnId()).isNotEqualTo("CVE-2020-25649");
            Assertions.assertThat(analysis.getVulnerability().getVulnId()).isNotEqualTo("CVE-2020-25650");
            Assertions.assertThat(analysis.isSuppressed()).isTrue();
            Assertions.assertThat(analysis.getAnalysisComments().size()).isEqualTo(3);
            Assertions.assertThat(analysis.getAnalysisComments()).satisfiesExactlyInAnyOrder(comment -> {
                Assertions.assertThat(comment.getCommenter()).isEqualTo("CycloneDX VEX");
                Assertions.assertThat(comment.getComment()).isEqualTo(String.format("Analysis: %s → %s", AnalysisState.NOT_SET, AnalysisState.FALSE_POSITIVE));
            }, comment -> {
                Assertions.assertThat(comment.getCommenter()).isEqualTo("CycloneDX VEX");
                Assertions.assertThat(comment.getComment()).isEqualTo("Details: Unit test");
            }, comment -> {
                Assertions.assertThat(comment.getCommenter()).isEqualTo("CycloneDX VEX");
                Assertions.assertThat(comment.getComment()).isEqualTo(String.format("Justification: %s → %s", AnalysisJustification.NOT_SET, AnalysisJustification.PROTECTED_BY_MITIGATING_CONTROL));
            });
            Assertions.assertThat(analysis.getAnalysisDetails()).isEqualTo("Unit test");
        });
    }

    @Test
    void shouldApplyOwaspRatingsFromVex() throws URISyntaxException, IOException, ParseException {
        // Arrange
        var project = qm.createProject("Acme Application", null, "2.0", null, null, null, true, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("2.0");
        component = qm.createComponent(component, false);

        // Create vulnerabilities that will receive OWASP ratings
        var vuln1 = new Vulnerability();
        vuln1.setVulnId("CVE-2024-12345");
        vuln1.setSource(Vulnerability.Source.NVD);
        vuln1.setSeverity(Severity.HIGH);
        vuln1.setComponents(List.of(component));
        vuln1 = qm.createVulnerability(vuln1, false);
        qm.addVulnerability(vuln1, component, AnalyzerIdentity.NONE);

        var vuln2 = new Vulnerability();
        vuln2.setVulnId("CVE-2024-54321");
        vuln2.setSource(Vulnerability.Source.NVD);
        vuln2.setSeverity(Severity.CRITICAL);
        vuln2.setComponents(List.of(component));
        vuln2 = qm.createVulnerability(vuln2, false);
        qm.addVulnerability(vuln2, component, AnalyzerIdentity.NONE);

        // Load VEX with OWASP ratings
        final byte[] vexBytes = Files.readAllBytes(Paths.get(getClass().getClassLoader().getResource("vex-with-owasp-ratings.json").toURI()));
        var parser = BomParserFactory.createParser(vexBytes);
        var vex = parser.parse(vexBytes);

        qm.getPersistenceManager().refreshAll();

        // Act
        vexImporter.applyVex(qm, vex, project);
        qm.getPersistenceManager().refreshAll();

        // Assert
        var refreshedVuln1 = qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD.name(), "CVE-2024-12345");
        Assertions.assertThat(refreshedVuln1).isNotNull();
        Assertions.assertThat(refreshedVuln1.getOwaspRRVector()).isNotNull();
        Assertions.assertThat(refreshedVuln1.getOwaspRRVector()).isEqualTo("SL:1/M:1/O:0/S:2/ED:1/EE:1/A:1/ID:1/LC:2/LI:1/LAV:1/LAC:1/FD:1/RD:1/NC:2/PV:2");
        Assertions.assertThat(refreshedVuln1.getOwaspRRLikelihoodScore()).isNotNull();
        Assertions.assertThat(refreshedVuln1.getOwaspRRTechnicalImpactScore()).isNotNull();
        Assertions.assertThat(refreshedVuln1.getOwaspRRBusinessImpactScore()).isNotNull();

        var refreshedVuln2 = qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD.name(), "CVE-2024-54321");
        Assertions.assertThat(refreshedVuln2).isNotNull();
        Assertions.assertThat(refreshedVuln2.getOwaspRRVector()).isNotNull();
        Assertions.assertThat(refreshedVuln2.getOwaspRRVector()).isEqualTo("SL:5/M:5/O:5/S:9/ED:3/EE:3/A:9/ID:9/LC:9/LI:9/LAV:9/LAC:9/FD:9/RD:9/NC:7/PV:9");
        Assertions.assertThat(refreshedVuln2.getOwaspRRLikelihoodScore()).isNotNull();
        Assertions.assertThat(refreshedVuln2.getOwaspRRTechnicalImpactScore()).isNotNull();
        Assertions.assertThat(refreshedVuln2.getOwaspRRBusinessImpactScore()).isNotNull();
        // Verify that scores are higher for the critical vulnerability
        Assertions.assertThat(refreshedVuln2.getOwaspRRLikelihoodScore())
                .isGreaterThan(refreshedVuln1.getOwaspRRLikelihoodScore());
    }

}
