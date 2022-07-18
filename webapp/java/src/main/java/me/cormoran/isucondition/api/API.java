package me.cormoran.isucondition.api;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import me.cormoran.isucondition.repository.IsuAssociationConfigMapper;
import me.cormoran.isucondition.repository.IsuConditionMapper;
import me.cormoran.isucondition.repository.IsuMapper;
import me.cormoran.isucondition.repository.UserMapper;
import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.lang.Nullable;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.sql.Date;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.random.RandomGenerator;
import java.util.stream.Collectors;

@RestController
@Slf4j
public class API {
    @Autowired
    JWTVerifier verifier;
    @Autowired
    HttpSession httpSession;
    @Autowired
    IsuMapper isuMapper;
    @Autowired
    IsuConditionMapper isuConditionMapper;
    @Autowired
    UserMapper userMapper;
    @Autowired
    IsuAssociationConfigMapper isuAssociationConfigMapper;

    @Data
    @Builder
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    static class GetIsuListResponse {
        long id;
        String jiaIsuUuid;
        String name;
        String character;
        @Nullable
        GetIsuConditionResponse latestIsuCondition;
    }

    @Data
    @Builder
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    static class GetIsuConditionResponse {
        String jiaIsuUuid;
        String isuName;
        Long timestamp;
        Boolean isSitting;
        String condition;
        String conditionLevel;
        String message;
    }

    @GetMapping("/api/isu")
    @Transactional
    public List<GetIsuListResponse> getIsuList() {
        String currentUserId = getCurrentUserId();

        return isuMapper
                .getIsuList(currentUserId)
                .stream()
                .map(isu -> GetIsuListResponse.builder()
                        .id(isu.getId())
                        .jiaIsuUuid(isu.getJiaIsuUuid())
                        .name(isu.getName())
                        .character(isu.getCharacter())
                        .latestIsuCondition(Optional
                                .ofNullable(isuConditionMapper.getIsuCondition(isu.getJiaIsuUuid()))
                                .map(condition ->
                                        GetIsuConditionResponse.builder()
                                                .jiaIsuUuid(condition.getJiaIsuUuid())
                                                .isuName(isu.getName())
                                                .timestamp(condition.getTimestamp().getTime() / 1000)
                                                .isSitting(condition.getIsSitting())
                                                .condition(condition.getCondition())
                                                .conditionLevel(toConditionLevel(condition.getCondition()))
                                                .message(condition.getMessage())
                                                .build())
                                .orElse(null))
                        .build()
                )
                .collect(Collectors.toList());
    }

    @PostMapping("/api/isu")
    @Transactional
    @ResponseStatus(HttpStatus.CREATED)
    public IsuMapper.Isu postIsu(@RequestParam(required = false) MultipartFile image,
                                 @RequestParam("isu_name") String isuName,
                                 @RequestParam("jia_isu_uuid") String jiaIsuUuid) throws IOException, URISyntaxException {
        String currentUserId = getCurrentUserId();

        final InputStream imageInput;
        if (image == null) {
            imageInput = Files.newInputStream(Path.of("../NoImage.jpg"), StandardOpenOption.READ);
        } else {
            imageInput = image.getInputStream();
        }
        isuMapper.insertIsu(jiaIsuUuid, isuName, imageInput.readAllBytes(), currentUserId);

        RestTemplate client = new RestTemplate(new SimpleClientHttpRequestFactory());
        var x = client.getMessageConverters();

        HttpHeaders headers = new HttpHeaders();

        String urlPrefix = isuAssociationConfigMapper.getJiaServiceUrl("jia_service_url");
        if (urlPrefix == null || urlPrefix.length() == 0)
            urlPrefix = "http://jiaapi-mock:5000";

        URI uri = new URI(urlPrefix + "/api/activate");
        headers.setContentType(MediaType.APPLICATION_JSON);


        RequestEntity<?> req = new RequestEntity<>(new JiaServiceRequest(Optional.ofNullable(System.getenv("POST_ISUCONDITION_TARGET_BASE_URL")).orElse("http://localhost:8080"), jiaIsuUuid), headers, HttpMethod.POST, uri);


        ResponseEntity<IsuFromJIA> res = client.exchange(req, IsuFromJIA.class);
        if (res.getStatusCode() != HttpStatus.ACCEPTED) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "JIAService returned error");
        }
        IsuFromJIA response = res.getBody();
        isuMapper.updateIsuCharacter(jiaIsuUuid, response.character);
        IsuMapper.Isu isu = isuMapper.getIsu(currentUserId, jiaIsuUuid);
        return isu;
    }

    @AllArgsConstructor
    @Data
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    static class JiaServiceRequest {
        String targetBaseUrl;
        String isuUuid;
    }

    @Data
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    static class IsuFromJIA {
        String character;
    }

    @GetMapping("/api/isu/{jiaIsuUuid}")
    public IsuMapper.Isu getIsuId(@PathVariable String jiaIsuUuid) {
        String currentUserId = getCurrentUserId();
        IsuMapper.Isu isu = isuMapper.getIsu(currentUserId, jiaIsuUuid);
        if (isu == null) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "not found: isu");
        return isu;
    }

    @GetMapping("/api/isu/{jiaIsuUuid}/icon")
    @ResponseBody
    public byte[] getIsuIcon(@PathVariable String jiaIsuUuid) {
        String currentUserId = getCurrentUserId();
        IsuMapper.Isu isu = isuMapper.getIsu(currentUserId, jiaIsuUuid);
        if (isu == null) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "not found: isu");
        return isu.getImage();
    }

    @Data
    @Builder
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    static class GraphDataPointWithInfo {
        String jiaIsuUuid;
        Timestamp startAt;
        GraphDataPoint data;
        Long[] conditionTimestamps;
    }

    @Builder
    @Data
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    static class GraphDataPoint {
        int score;
        ConditionsPercentage percentage;
    }

    @Data
    @Builder
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    static class ConditionsPercentage {
        int sitting;
        int isBroken;
        int isDirty;
        int isOverweight;
    }

    @Data
    @AllArgsConstructor
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    static class GraphResponse {
        Long startAt;
        Long endAt;
        @Nullable
        GraphDataPoint data;
        Long[] conditionTimestamps;
    }

    @GetMapping("/api/isu/{jiaIsuUuid}/graph")
    public List<GraphResponse> getIsuGraph(@PathVariable String jiaIsuUuid,
                            @RequestParam(value = "datetime", required = false) String datetimeStr) {
        if (datetimeStr == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "missing: datetime");
        Long datetime;
        try {
            datetime = Long.parseLong(datetimeStr);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "bad format: datetime");
        }
        String currentUserId = getCurrentUserId();
        if (isuMapper.countIsu2(jiaIsuUuid, currentUserId) == 0) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "not found: isu");
        }
        AtomicReference<Long> startTimeInThisHour = new AtomicReference(0l);
        AtomicReference<List<IsuConditionMapper.IsuCondition>> conditionsInThisHour = new AtomicReference<>(new ArrayList<>());
        AtomicReference<List<Long>> timestampInThisHour = new AtomicReference<>(new ArrayList<>());
        List<GraphDataPointWithInfo> dataPoints = new ArrayList<>();
        Runnable processDataPoints = () -> {
            if (conditionsInThisHour.get().size() == 0) {
                return;
            }

            ConditionsPercentage count = ConditionsPercentage.builder().build();
            AtomicReference<Integer> rawScore = new AtomicReference<>(0);
            AtomicInteger sittingCount = new AtomicInteger();
            conditionsInThisHour.get().forEach(condition -> {
                if (!validateConditionFormat(condition.getCondition())) {
                    throw new IllegalStateException();
                }
                int badConditionsCount = 0;
                for (String conditionItem : condition.getCondition().split(",")) {
                    String[] keyValue = conditionItem.split("=");
                    if (keyValue[1].equals("true")) {
                        if (keyValue[0].equals("is_broken")) {
                            count.isBroken++;
                        } else if (keyValue[0].equals("is_dirty")) {
                            count.isDirty++;
                        } else if (keyValue[0].equals("is_overweight")) {
                            count.isOverweight++;
                        }
                        badConditionsCount++;
                    }
                }
                if (badConditionsCount >= 3) {
                    rawScore.updateAndGet(v -> v + 1);
                } else if (badConditionsCount >= 1) {
                    rawScore.updateAndGet(v -> v + 2);
                } else {
                    rawScore.updateAndGet(v -> v + 3);
                }
                if (condition.getIsSitting()) {
                    sittingCount.getAndIncrement();
                }
            });
            // calc
            int length = conditionsInThisHour.get().size();
            dataPoints.add(GraphDataPointWithInfo.builder()
                            .jiaIsuUuid(jiaIsuUuid)
                            .startAt(new Timestamp(startTimeInThisHour.get() * 1000))
                            .data(GraphDataPoint.builder()
                                    .score(rawScore.get() * 100 / 3 / length)
                                    .percentage(ConditionsPercentage.builder()
                                            .sitting(sittingCount.get() * 100 / length)
                                            .isBroken(count.isBroken * 100 / length)
                                            .isOverweight(count.isOverweight * 100 / length)
                                            .isDirty(count.isDirty * 100 / length)
                                            .build())
                                    .build())
                            .conditionTimestamps(timestampInThisHour.get().toArray(Long[]::new))
                            .build());
            conditionsInThisHour.set(new ArrayList<>());
            timestampInThisHour.set(new ArrayList<>());
        };
        isuConditionMapper.getIsuConditionsByAsc(jiaIsuUuid)
                .forEach(condition -> {
                    Long truncatedTime = condition.getTimestamp().toInstant().truncatedTo(ChronoUnit.HOURS).getEpochSecond();
                    if (!startTimeInThisHour.get().equals(truncatedTime)) {
                        processDataPoints.run();
                        startTimeInThisHour.set(truncatedTime);
                    }
                    conditionsInThisHour.get().add(condition);
                    timestampInThisHour.get().add(condition.getTimestamp().toInstant().getEpochSecond());
                });
        processDataPoints.run();

        Timestamp graphDate = new Timestamp(Instant.ofEpochSecond(datetime).truncatedTo(ChronoUnit.HOURS).getEpochSecond() * 1000);
        Timestamp endTime = new Timestamp(graphDate.getTime() + Duration.ofDays(1).toMillis());
        int startIndex = dataPoints.size();
        int endNextIndex = dataPoints.size();
        for (int i = 0; i < dataPoints.size(); i++) {
            if (startIndex == dataPoints.size() && !dataPoints.get(i).startAt.before(graphDate)) {
                startIndex = i;
            }
            if (endNextIndex == dataPoints.size() && dataPoints.get(i).startAt.after(endTime)) {
                endNextIndex = i;
            }
        }
        final List<GraphDataPointWithInfo> filteredDataPoints;
        if (startIndex < endNextIndex) {
            filteredDataPoints = dataPoints.subList(startIndex, endNextIndex);
        } else {
            filteredDataPoints = new ArrayList<>();
        }
        Timestamp thisTime = new Timestamp(graphDate.getTime());
        int index = 0;
        List<GraphResponse> responses = new ArrayList<>();
        while (thisTime.before(endTime)) {
            GraphDataPoint data = null;
            Long[] timestamps = new Long[0];
            if (index < filteredDataPoints.size()) {
                if (filteredDataPoints.get(index).startAt.equals(thisTime)) {
                    data = filteredDataPoints.get(index).data;
                    timestamps = filteredDataPoints.get(index).conditionTimestamps;
                    index++;
                }
            }
            responses.add(new GraphResponse(
                    thisTime.getTime() / 1000,
                    (thisTime.getTime() + Duration.ofHours(1).toMillis()) / 1000,
                    data,
                    timestamps));

            thisTime = new Timestamp(thisTime.getTime() + Duration.ofHours(1).toMillis());
        }
        return responses;
    }

    @GetMapping("/api/condition/{jiaIsuUuid}")
    public List<GetIsuConditionResponse> getIsuConditions(@PathVariable String jiaIsuUuid,
                                                          @RequestParam(value = "end_time", required = false) String endTimeStr,
                                                          @RequestParam(value = "condition_level", required = false) String conditionLevel,
                                                          @RequestParam(value = "start_time", required = false) String startTimeStr) {
        if (endTimeStr == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "bad format: end_time");
        Long endTime;
        try {
            endTime = Long.parseLong(endTimeStr);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "bad format: end_time");
        }
        if (conditionLevel == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "missing: condition_level");
        Set<String> conditionLevels = Arrays.stream(conditionLevel.split(",")).collect(Collectors.toSet());
        String currentUserId = getCurrentUserId();

        String name = Optional.ofNullable(isuMapper.getIsu(currentUserId, jiaIsuUuid)).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "not found: isu")).getName();

        final List<IsuConditionMapper.IsuCondition> conditions;
        if (startTimeStr != null) {
            Long startTime;
            try {
                startTime = Long.parseLong(startTimeStr);
            } catch (Exception e) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "bad format: start_time");
            }
            // conditions = isuConditionMapper.getIsuConditionWithRange(jiaIsuUuid, new Timestamp(startTime * 1000 + Duration.ofHours(9).toMillis()), new Timestamp(endTime * 1000 + Duration.ofHours(9).toMillis()));
            conditions = isuConditionMapper.getIsuConditionWithRange(jiaIsuUuid, new Timestamp(startTime * 1000), new Timestamp(endTime * 1000));
        } else {
            // conditions = isuConditionMapper.getIsuConditionWithEnd(jiaIsuUuid, new Timestamp(endTime * 1000 + Duration.ofHours(9).toMillis()));
            conditions = isuConditionMapper.getIsuConditionWithEnd(jiaIsuUuid, new Timestamp(endTime * 1000));
        }
        return conditions.stream()
                .filter(condition -> conditionLevels.contains(toConditionLevel(condition.getCondition())))
                .limit(20)
                .map(condition -> GetIsuConditionResponse.builder()
                        .jiaIsuUuid(condition.getJiaIsuUuid())
                        .isuName(name)
                        .timestamp(condition.getTimestamp().getTime() / 1000)
                        .isSitting(condition.getIsSitting())
                        .condition(condition.getCondition())
                        .conditionLevel(toConditionLevel(condition.getCondition()))
                        .message(condition.getMessage())
                        .build())
                .collect(Collectors.toList());
    }

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    static class PostIsuConditionRequest {
        boolean isSitting;
        String condition;
        String message;
        Long timestamp;
    }

    @PostMapping("/api/condition/{jiaIsuUuid}")
    @ResponseStatus(HttpStatus.ACCEPTED)
    @Transactional
    public void postIsuCondition(@PathVariable String jiaIsuUuid,
                                 @RequestBody List<PostIsuConditionRequest> requests) {
        if (RandomGenerator.getDefault().nextDouble() <= 0.9) {
            return;
        }

        if (isuMapper.countIsu(jiaIsuUuid) == 0) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        requests.forEach(req -> {
            log.info("req: {}", req);
            if (!validateConditionFormat(req.condition)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
            }
            isuConditionMapper.insertCondition(jiaIsuUuid, new Timestamp(req.timestamp * 1000), req.isSitting, req.condition, req.message);
        });
    }

    @Data
    @AllArgsConstructor
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    static class TrendResponse {
        String character;
        @Nullable
        List<TrendCondition> info;
        @Nullable
        List<TrendCondition> warning;
        @Nullable
        List<TrendCondition> critical;
    }

    @Data
    @AllArgsConstructor
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    static class TrendCondition {
        long isuId;
        long timestamp;
    }

    @GetMapping("/api/trend")
    public List<TrendResponse> getTrend() {
        return isuMapper.getCharacters()
                .stream()
                .map(character -> {
                    List<TrendCondition> info = new ArrayList<>();
                    List<TrendCondition> warning = new ArrayList<>();
                    List<TrendCondition> critical = new ArrayList<>();
                    isuMapper.getIsuListByCharacters(character)
                            .forEach(isu -> {
                                List<IsuConditionMapper.IsuCondition> conditions = isuConditionMapper.getIsuConditions(isu.getJiaIsuUuid());
                                if (conditions.size() > 0) {
                                    IsuConditionMapper.IsuCondition condition = conditions.get(0);
                                    TrendCondition trendCondition = new TrendCondition(isu.getId(), condition.getTimestamp().getTime() / 1000);
                                    switch (toConditionLevel(condition.getCondition())) {
                                        case "info":
                                            info.add(trendCondition);
                                            break;
                                        case "warning":
                                            warning.add(trendCondition);
                                            break;
                                        case "critical":
                                            critical.add(trendCondition);
                                            break;
                                    }
                                }
                            });
                    info.sort(Comparator.comparing(TrendCondition::getTimestamp).reversed());
                    warning.sort(Comparator.comparing(TrendCondition::getTimestamp).reversed());
                    critical.sort(Comparator.comparing(TrendCondition::getTimestamp).reversed());
                    log.info("info {}", info);
                    log.info("warning {}", warning);
                    log.info("critical {}", critical);
                    return new TrendResponse(character, info, warning, critical);
                })
                .collect(Collectors.toList());
    }

    @PostMapping("/api/auth")
    public void postAuthentication(@RequestHeader(value = "Authorization", required = false) String authorizationHeader) {
        if (authorizationHeader == null) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "forbidden");
        }
        log.info(authorizationHeader);
        String reqJwt = authorizationHeader.startsWith("Bearer ") ? authorizationHeader.substring("Bearer ".length()) : authorizationHeader;
        final DecodedJWT jwt;
        try {
            jwt = verifier.verify(reqJwt);
        } catch (Exception e) {
            log.warn("failed to authenticate:<{}><{}>", authorizationHeader, e);
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "forbidden");
        }

        Claim claim = jwt.getClaim("jia_user_id");
        if (claim.asInt() != null) {
            new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid JWT payload");
        }
        Optional.ofNullable(claim.asString())
                .ifPresentOrElse(userId -> {
                    log.warn("userId: " + userId);
                    userMapper.insertUser(userId);
                    httpSession.setAttribute("USER_ID", userId);
                }, () -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid JWT payload"));
    }

    @PostMapping(value = "/api/signout", produces = "text/plain")
    @ResponseBody
    public String postSignout() {
        String currentUserId = getCurrentUserId();
        httpSession.invalidate();
        return "done";
    }

    @Data
    @AllArgsConstructor
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    static class GetMeResponse {
        String jiaUserId;
    }

    @GetMapping("/api/user/me")
    public GetMeResponse getMe() {
        return new GetMeResponse(getCurrentUserId());
    }

    @GetMapping({
            "/",
            "/register"
    })
    public ModelAndView getIndex() {
        return new ModelAndView("index.html");
    }

    @GetMapping({
            "/isu/{jiaIsuUuid}",
            "/isu/{jiaIsuUuid}/condition",
            "/isu/{jiaIsuUuid}/graph",
    })
    public ModelAndView getIndex(@PathVariable String jiaIsuUuid) {
        return new ModelAndView("/index.html");
    }

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    static class InitalizeRequest {
        String jiaServiceUrl;
    }

    @PostMapping("/initialize")
    public Map<String, String> initialize(@RequestBody InitalizeRequest request) throws IOException, InterruptedException {
        Process process = Runtime.getRuntime().exec("../sql/init.sh");
        process.waitFor();
        try (InputStream stream = process.getInputStream()) {
            log.info(stream.readAllBytes().toString());
        }
        try (InputStream stream = process.getErrorStream()) {
            log.info(stream.readAllBytes().toString());
        }
        process.destroy();
        isuAssociationConfigMapper.insertJiaServiceUrl("jia_service_url", Optional.ofNullable(request.jiaServiceUrl).orElse(""));
        return Map.of("language", "java");
    }

    String getCurrentUserId() {
        String userId = (String) httpSession.getAttribute("USER_ID");
        if (userId == null || userMapper.countUser(userId) == 0) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "you are not signed in");
        }
        return userId;
    }

    String toConditionLevel(String condition) {
        long size = Arrays.stream(condition.split(",")).filter(cond -> cond.contains("=true")).count();
        if (size == 0) return "info";
        else if (size == 1 || size == 2) return "warning";
        else if (size == 3) return "critical";
        else throw new IllegalArgumentException("unknown " + condition);
    }

    boolean validateConditionFormat(String condition) {
        String[] keys = new String[]{"is_dirty=", "is_overweight=", "is_broken="};
        for (int i = 0; i < keys.length; i++) {
            if (!condition.startsWith(keys[i])) {
                return false;
            }
            condition = condition.substring(keys[i].length());
            if (condition.startsWith("true")) {
                condition = condition.substring("true".length());
            } else if (condition.startsWith("false")) {
                condition = condition.substring("false".length());
            } else {
                return false;
            }
            if (i + 1 < keys.length) {
                if (condition.startsWith(",")) {
                    condition = condition.substring(1);
                } else {
                    return false;
                }
            }
        }
        return condition.length() == 0;
    }
}
