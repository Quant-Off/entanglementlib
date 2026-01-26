/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.strategy.detail.hybrid;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.exception.critical.EntLibNativeError;
import space.qu4nt.entanglementlib.exception.critical.EntLibSecurityError;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalStateException;
import space.qu4nt.entanglementlib.exception.secure.crypto.EntLibCryptoKEMProcessingException;
import space.qu4nt.entanglementlib.security.crypto.EntLibAlgorithmType;
import space.qu4nt.entanglementlib.security.crypto.EntLibCryptoRegistry;
import space.qu4nt.entanglementlib.security.crypto.KEMType;
import space.qu4nt.entanglementlib.security.crypto.ParameterSizeDetail;
import space.qu4nt.entanglementlib.security.crypto.strategy.NativeKEMStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.MLKEMStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.X25519Strategy;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/// X25519 ECDH와 ML-KEM-768 양자-내성 키 캡슐화 메커니즘을 결합한 하이브리드 전략 클래스입니다.
///
/// 이 클래스는 [SensitiveDataContainer]의 바인딩(Binding) 기능을 활용하여
/// 공유 비밀(SS)과 암호문(CT)을 논리적으로 연결하고, [ParameterSizeDetail]을 통해
/// 복합적인 파라미터 사이즈를 관리합니다.
///
/// ## 키 결합 구조
/// 
/// - 공개키(PK): `PK_X25519 || PK_MLKEM768`
/// - 비밀키(SK): `SK_X25519 || SK_MLKEM768`
/// - 암호문(CT): `CT_X25519 || CT_MLKEM768` (SS 컨테이너에 바인딩됨)
/// - 공유 비밀(SS): `SS_X25519 || SS_MLKEM768`
///
/// @author Q. T. Felix
/// @since 1.1.0
@Slf4j
public final class X25519MLKEM768Strategy implements NativeKEMStrategy {

    @Setter
    @Nullable
    private X25519Strategy x25519Strategy;
    @Setter
    @Nullable
    private MLKEMStrategy mlkemStrategy;

    // 하이브리드 알고리즘 규격 정의
    private final ParameterSizeDetail hybridDetail;
    private final ParameterSizeDetail x25519Detail;
    private final ParameterSizeDetail mlkemDetail;

    private final KEMType type = KEMType.X25519MLKEM768;

    private X25519MLKEM768Strategy(final @Nullable X25519Strategy x25519Strategy, final @Nullable MLKEMStrategy mlkemStrategy) {
        this.x25519Strategy = x25519Strategy;
        this.mlkemStrategy = mlkemStrategy;

        // 파라미터 사이즈 상세 초기화
        this.x25519Detail = KEMType.X25519.getParameterSizeDetail();
        this.mlkemDetail = KEMType.ML_KEM_768.getParameterSizeDetail();
        this.hybridDetail = KEMType.X25519MLKEM768.getParameterSizeDetail();
    }

    /// X25519MLKEM768Strategy 인스턴스를 생성합니다.
    ///
    /// [EntLibCryptoRegistry] 레지스트리 등록용 팩토리 메소드입니다.
    ///
    /// @return 새 하이브리드 전략 인스턴스
    @ApiStatus.Internal
    public static X25519MLKEM768Strategy create(final X25519Strategy x25519Strategy, final MLKEMStrategy mlkemStrategy) {
        return new X25519MLKEM768Strategy(x25519Strategy, mlkemStrategy);
    }

    /// 하이브리드 캡슐화를 수행합니다.
    ///
    /// 1. 입력된 하이브리드 공개키를 분리합니다.
    /// 2. X25519와 ML-KEM의 `encapsulate`를 각각 수행합니다.
    /// 3. 결과로 나온 공유 비밀(SS)들을 병합합니다.
    /// 4. 각 전략 결과에 바인딩된 암호문(CT)들을 추출하여 병합 후, 최종 SS 컨테이너에 바인딩합니다.
    ///
    /// @param keyPublic 하이브리드 공개키 컨테이너
    /// @return 하이브리드 공유 비밀(SS)과 바인딩된 암호문(CT)을 포함하는 컨테이너
    @Override
    public SensitiveDataContainer encapsulate(@NotNull SensitiveDataContainer keyPublic)
            throws EntLibCryptoKEMProcessingException, EntLibSecureIllegalStateException {
        if (x25519Strategy == null || mlkemStrategy == null)
            throw new EntLibSecureIllegalStateException("X25519MLKEM768 알고리즘에 대한 캡슐화를 수행할 수 없습니다! 이 작업을 수행하기 전에 X25519, ML-KEM-768 스트레티지를 생성해야 합니다.");
        long inputSize = keyPublic.getMemorySegment().byteSize();
        if (inputSize != hybridDetail.getEncapsulationKeySize()) {
            throw new EntLibCryptoKEMProcessingException(
                    "주요 데이터의 바이트 사이즈가 올바르지 않습니다! 세션 체계 참여자가 악의적인 데이터를 전송했을 수 있습니다."
            );
        }

        // 1. 하위 컨테이너 준비 (Resource Management)
        SensitiveDataContainer x25519Pk = null;
        SensitiveDataContainer mlkemPk = null;
        SensitiveDataContainer x25519Res = null;
        SensitiveDataContainer mlkemRes = null;

        // 최종 결과 컨테이너
        SensitiveDataContainer hybridSs = new SensitiveDataContainer(hybridDetail.getSharedSecretKeySize());

        try {
            MemorySegment pkSeg = keyPublic.getMemorySegment();
            long xPkSize = x25519Detail.getEncapsulationKeySize();
            long mPkSize = mlkemDetail.getEncapsulationKeySize();

            // 2. 공개키 분리 및 컨테이너 생성
            // toArray()로 힙에 복사 후 SensitiveDataContainer에 전달하며 forceWipe=true 설정.
            // 컨테이너가 데이터를 가져간 후 원본 배열을 즉시 소거하여 메모리 잔류를 방지함.
            x25519Pk = new SensitiveDataContainer(
                    pkSeg.asSlice(0, xPkSize).toArray(ValueLayout.JAVA_BYTE),
                    true
            );
            mlkemPk = new SensitiveDataContainer(
                    pkSeg.asSlice(xPkSize, mPkSize).toArray(ValueLayout.JAVA_BYTE),
                    true
            );

            // 3. 위임 (Delegation)
            // x25519Res: SS 포함, 내부 bindings[0]에 CT 포함
            x25519Res = x25519Strategy.encapsulate(x25519Pk);
            mlkemRes = mlkemStrategy.encapsulate(mlkemPk);

            // 4. 공유 비밀(SS) 병합
            MemorySegment ssTarget = hybridSs.getMemorySegment();
            long xSsSize = x25519Detail.getSharedSecretKeySize();
            long mSsSize = mlkemDetail.getSharedSecretKeySize();

            ssTarget.asSlice(0, xSsSize).copyFrom(x25519Res.getMemorySegment());
            ssTarget.asSlice(xSsSize, mSsSize).copyFrom(mlkemRes.getMemorySegment());

            // 5. 암호문(CT) 병합 및 바인딩
            // 각 전략의 결과 컨테이너에서 암호문 컨테이너 추출 (Index 0 가정)
            @SuppressWarnings("resource") SensitiveDataContainer xCtContainer = x25519Res.get(0)
                    .orElseThrow(() -> new EntLibCryptoKEMProcessingException("X25519 암호문 컨테이너 누락"));
            @SuppressWarnings("resource") SensitiveDataContainer mCtContainer = mlkemRes.get(0)
                    .orElseThrow(() -> new EntLibCryptoKEMProcessingException("ML-KEM 암호문 컨테이너 누락"));

            // 하이브리드 CT 컨테이너 생성 및 SS에 바인딩
            SensitiveDataContainer hybridCt = hybridSs.addContainerData(hybridDetail.getCiphertextSize());
            MemorySegment ctTarget = hybridCt.getMemorySegment();
            long xCtSize = x25519Detail.getCiphertextSize();
            long mCtSize = mlkemDetail.getCiphertextSize();

            ctTarget.asSlice(0, xCtSize).copyFrom(xCtContainer.getMemorySegment());
            ctTarget.asSlice(xCtSize, mCtSize).copyFrom(mCtContainer.getMemorySegment());

            return hybridSs;

        } catch (Throwable e) {
            hybridSs.close(); // 예외 발생 시 생성된 결과물 소거
            throw new EntLibNativeError("네이티브 에러", e);
        } finally {
            // 중간 컨테이너 리소스 해제
            if (x25519Pk != null) x25519Pk.close();
            if (mlkemPk != null) mlkemPk.close();
            if (x25519Res != null) x25519Res.close();
            if (mlkemRes != null) mlkemRes.close();
        }
    }

    /// 하이브리드 디캡슐화를 수행합니다.
    ///
    /// @param secretKeyContainer 하이브리드 비밀키
    /// @param ciphertext         하이브리드 암호문 (바인딩된 구조가 아닌, 직렬화된 CT 블록을 가정)
    /// @return 복원된 하이브리드 공유 비밀
    @Override
    public SensitiveDataContainer decapsulate(@NotNull SensitiveDataContainer secretKeyContainer,
                                              @NotNull SensitiveDataContainer ciphertext) throws EntLibSecureIllegalStateException {
        if (x25519Strategy == null || mlkemStrategy == null)
            throw new EntLibSecureIllegalStateException("X25519MLKEM768 알고리즘에 대한 디캡슐화를 수행할 수 없습니다! 이 작업을 수행하기 전에 X25519, ML-KEM-768 스트레티지를 생성해야 합니다.");
        long ctSize = ciphertext.getMemorySegment().byteSize();
        if (ctSize != hybridDetail.getCiphertextSize()) {
            throw new EntLibSecurityError("하이브리드 암호문 사이즈 불일치");
        }

        SensitiveDataContainer xSk = null;
        SensitiveDataContainer mSk = null;
        SensitiveDataContainer xCt = null;
        SensitiveDataContainer mCt = null;
        SensitiveDataContainer xSs = null;
        SensitiveDataContainer mSs = null;

        SensitiveDataContainer hybridSs = new SensitiveDataContainer(hybridDetail.getSharedSecretKeySize());

        try {
            MemorySegment skSeg = secretKeyContainer.getMemorySegment();
            MemorySegment ctSeg = ciphertext.getMemorySegment();

            long xSkSize = x25519Detail.getDecapsulationKeySize(); // typically 32
            long mSkSize = mlkemDetail.getDecapsulationKeySize();
            long xCtSize = x25519Detail.getCiphertextSize();
            long mCtSize = mlkemDetail.getCiphertextSize();

            // 1. 데이터 분할 (Copy with wiping source)
            xSk = new SensitiveDataContainer(skSeg.asSlice(0, xSkSize).toArray(ValueLayout.JAVA_BYTE), true);
            mSk = new SensitiveDataContainer(skSeg.asSlice(xSkSize, mSkSize).toArray(ValueLayout.JAVA_BYTE), true);

            xCt = new SensitiveDataContainer(ctSeg.asSlice(0, xCtSize).toArray(ValueLayout.JAVA_BYTE), true);
            mCt = new SensitiveDataContainer(ctSeg.asSlice(xCtSize, mCtSize).toArray(ValueLayout.JAVA_BYTE), true);

            // 2. 위임
            xSs = x25519Strategy.decapsulate(xSk, xCt);
            mSs = mlkemStrategy.decapsulate(mSk, mCt);

            // 3. SS 병합
            MemorySegment target = hybridSs.getMemorySegment();
            long xSsSize = x25519Detail.getSharedSecretKeySize();
            long mSsSize = mlkemDetail.getSharedSecretKeySize();

            target.asSlice(0, xSsSize).copyFrom(xSs.getMemorySegment());
            target.asSlice(xSsSize, mSsSize).copyFrom(mSs.getMemorySegment());

        } catch (Throwable e) {
            hybridSs.close();
            throw new EntLibNativeError("네이티브 에러", e);
        } finally {
            if (xSk != null) xSk.close();
            if (mSk != null) mSk.close();
            if (xCt != null) xCt.close();
            if (mCt != null) mCt.close();
            if (xSs != null) xSs.close();
            if (mSs != null) mSs.close();
        }

        return hybridSs;
    }

    @Override
    public String getAlgorithmName() {
        return "X25519-ML-KEM-768";
    }

    @Override
    public EntLibAlgorithmType getAlgorithmType() {
        return type;
    }
}