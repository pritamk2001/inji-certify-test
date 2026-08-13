package io.mosip.certify.utils;

import io.mosip.certify.core.dto.*;
import io.mosip.certify.entity.Issuer;
import io.mosip.certify.entity.attributes.MetaDataDisplay;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class IssuerMapper {

    public IssuerDTO toDto(Issuer issuer) {
        if (issuer == null) {
            return null;
        }
        IssuerDTO dto = new IssuerDTO();
        dto.setIssuerId(issuer.getIssuerId());
        dto.setStatus(issuer.getStatus());
        dto.setCredentialIssuerUrl(issuer.getCredentialIssuerUrl());
        dto.setIdentifier(issuer.getIdentifier());
        dto.setDidUrl(issuer.getDidUrl());
        dto.setDisplay(mapDisplayToDto(issuer.getDisplay()));
        dto.setAuthorizationServers(issuer.getAuthorizationServers());
        dto.setKeyManagerAppId(issuer.getKeyManagerAppId());
        dto.setKeyManagerRefId(issuer.getKeyManagerRefId());
        dto.setSignatureCryptoSuite(issuer.getSignatureCryptoSuite());
        dto.setSignatureAlgo(issuer.getSignatureAlgo());
        dto.setMdocIacaAppId(issuer.getMdocIacaAppId());
        dto.setMdocIacaRefId(issuer.getMdocIacaRefId());
        dto.setMdocDsAppId(issuer.getMdocDsAppId());
        dto.setMdocDsRefId(issuer.getMdocDsRefId());
        return dto;
    }

    public List<MetaDataDisplay> mapDisplayToEntity(List<MetaDataDisplayDTO> display) {
        if (display == null) {
            return Collections.emptyList();
        }
        return display.stream().map(this::mapDisplayItem).collect(Collectors.toList());
    }

    private MetaDataDisplay mapDisplayItem(MetaDataDisplayDTO dto) {
        MetaDataDisplay entity = new MetaDataDisplay();
        entity.setName(dto.getName());
        entity.setLocale(dto.getLocale());
        entity.setTextColor(dto.getTextColor());
        entity.setBackgroundColor(dto.getBackgroundColor());
        if (dto.getLogo() != null) {
            entity.setLogo(new MetaDataDisplay.Logo(dto.getLogo().getUrl(), dto.getLogo().getAltText()));
        }
        if (dto.getBackgroundImage() != null) {
            entity.setBackgroundImage(new MetaDataDisplay.BackgroundImage(dto.getBackgroundImage().getUri()));
        }
        return entity;
    }

    private List<MetaDataDisplayDTO> mapDisplayToDto(List<MetaDataDisplay> display) {
        if (display == null) {
            return Collections.emptyList();
        }
        return display.stream().map(this::mapDisplayItemToDto).collect(Collectors.toList());
    }

    private MetaDataDisplayDTO mapDisplayItemToDto(MetaDataDisplay entity) {
        MetaDataDisplayDTO dto = new MetaDataDisplayDTO();
        dto.setName(entity.getName());
        dto.setLocale(entity.getLocale());
        dto.setTextColor(entity.getTextColor());
        dto.setBackgroundColor(entity.getBackgroundColor());
        if (entity.getLogo() != null) {
            MetaDataDisplayDTO.Logo logo = new MetaDataDisplayDTO.Logo();
            logo.setUrl(entity.getLogo().getUrl());
            logo.setAltText(entity.getLogo().getAltText());
            dto.setLogo(logo);
        }
        if (entity.getBackgroundImage() != null) {
            MetaDataDisplayDTO.BackgroundImage bg = new MetaDataDisplayDTO.BackgroundImage();
            bg.setUri(entity.getBackgroundImage().getUri());
            dto.setBackgroundImage(bg);
        }
        return dto;
    }
}
