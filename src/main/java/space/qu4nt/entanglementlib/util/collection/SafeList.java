/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.util.collection;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.resource.language.LanguageInstanceBased;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * 동기적으로 안전하게 컬렉션 작업을 수행하기 위한 클래스입니다.
 * 내부적으로 {@link ArrayList} 객체에 대한 접근을 동기적으로 합니다.
 *
 * @param <T>
 * @author Q. T. Felix
 * @since 1.1.0
 */
public class SafeList<T> implements Iterable<T> {

    @SuppressWarnings({"rawtypes"})
    private static final LanguageInstanceBased<SafeList> lang = LanguageInstanceBased.create(SafeList.class);

    private final ArrayList<T> list = new ArrayList<>();

    /**
     * 기존 {@link List}를 받아 {@link SafeList}로 변환하는 정적 메소드입니다.
     * 입력된 리스트의 모든 요소를 새로운 {@code SafeList}에 복사합니다.
     *
     * @param list 변환할 리스트
     * @param <T>  요소 타입
     * @return 변환된 {@code SafeList} 인스턴스
     * @throws NullPointerException 입력 리스트가 {@code null}인 경우
     */
    public static <T> SafeList<T> from(List<T> list) {
        Objects.requireNonNull(list);
        SafeList<T> safeList = new SafeList<>();
        for (T item : list)
            safeList.add(item);
        return safeList;
    }

    public synchronized void add(T item) {
        list.add(item);
    }

    public synchronized void add(int index, T item) {
        list.add(index, item);
    }

    public synchronized T remove(int index) {
        if (index < 0 || index >= list.size())
            throw new IndexOutOfBoundsException(lang.argsNonTopKey("index-out-of-bounds-exc", index, list.size()));
        return list.remove(index);
    }

    public synchronized boolean remove(T item) {
        return list.remove(item);
    }

    public synchronized T get(int index) {
        if (index < 0 || index >= list.size())
            throw new IndexOutOfBoundsException(lang.argsNonTopKey("index-out-of-bounds-exc", index, list.size()));
        return list.get(index);
    }

    public synchronized T set(int index, T item) {
        if (index < 0 || index >= list.size())
            throw new IndexOutOfBoundsException(lang.argsNonTopKey("index-out-of-bounds-exc", index, list.size()));
        return list.set(index, item);
    }

    public synchronized boolean isEmpty() {
        return list.isEmpty();
    }

    public synchronized int size() {
        return list.size();
    }

    public synchronized void clear() {
        list.clear();
    }

    public synchronized boolean contains(T item) {
        return list.contains(item);
    }

    public synchronized int indexOf(T item) {
        return list.indexOf(item);
    }

    /**
     * 이 리스트의 요소들에 대한 순차 스트림을 반환하는 메소드입니다.
     * 스트림은 이 리스트의 요소들을 순회하는 데 사용할 수 있습니다.
     *
     * @return 이 리스트의 요소들에 대한 순차 스트림
     */
    public synchronized Stream<T> stream() {
        return list.stream();
    }

    /**
     * 원자적으로 아이템을 추가하는 메소드입니다. 아이템이 존재하지 않으면 추가합니다.
     * 멀티스레드 환경에서 중복 추가를 방지하기 위해 설계되었습니다.
     * 표준 {@code synchronized} 리스트에서 직접 지원되지 않는 기능입니다.
     *
     * @param item 추가할 아이템
     * @return 추가되었으면 true, 이미 존재하여 추가되지 않았으면 false
     */
    public synchronized boolean addIfAbsent(T item) {
        if (!list.contains(item)) {
            list.add(item);
            return true;
        }
        return false;
    }

    /**
     * {@code T} 타입의 요소에 대한 반복자를 반환합니다.
     *
     * @return 반복자
     */
    @Override
    public synchronized @NotNull Iterator<T> iterator() {
        return list.iterator();
    }

    @Override
    public String toString() {
        return "SafeList{" +
                "items=" + list +
                '}';
    }
}
